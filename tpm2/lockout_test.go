package tpm2

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type lockoutTestClock struct {
	mu  sync.Mutex
	now time.Time
}

type lockoutFailStore struct {
	inner *MemoryLockoutStore
	mu    sync.Mutex
	fail  bool
}

var errLockoutTestStorage = errors.New("lockout test storage failure")

func (s *lockoutFailStore) Load() ([]byte, error) {
	return s.inner.Load()
}

func (s *lockoutFailStore) Save(data []byte) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return errLockoutTestStorage
	}
	return s.inner.Save(data)
}

func (s *lockoutFailStore) SetFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

func newLockoutTestClock(now time.Time) *lockoutTestClock {
	return &lockoutTestClock{now: now.UTC()}
}

func (c *lockoutTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lockoutTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func mustNewLockout(t *testing.T, store LockoutStore, policy DictionaryAttackPolicy, opts LockoutOptions) *Lockout {
	t.Helper()
	lockout, err := NewLockout(store, policy, opts)
	if err != nil {
		t.Fatalf("NewLockout() = %v", err)
	}
	return lockout
}

func mustBeginLockoutAttempt(t *testing.T, lockout *Lockout) *LockoutAttempt {
	t.Helper()
	attempt, err := lockout.Begin()
	if err != nil {
		t.Fatalf("Begin() = %v", err)
	}
	return attempt
}

func mustFailLockoutAttempt(t *testing.T, attempt *LockoutAttempt) {
	t.Helper()
	if err := attempt.Fail(); err != nil {
		t.Fatalf("Fail() = %v", err)
	}
}

func TestLockoutResetAndLateFailureCommitAtomically(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 5, RecoveryTime: 60, LockoutRecovery: 60}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, policy, opts)

	late := mustBeginLockoutAttempt(t, lockout)
	before := lockout.Snapshot()

	reset, err := lockout.Reset([]byte("lockout"))
	if err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	if reset.Generation != before.Generation+1 {
		t.Errorf("Reset generation = %d, want %d", reset.Generation, before.Generation+1)
	}
	if reset.FailedTries != 0 || reset.Reserved != 0 {
		t.Errorf("Reset left failed=%d reserved=%d, want 0/0", reset.FailedTries, reset.Reserved)
	}
	if reset.Policy != policy {
		t.Errorf("Reset policy = %+v, want %+v", reset.Policy, policy)
	}

	if err := late.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("late Fail() = %v, want ErrStaleLockoutResponse", err)
	}
	if err := lockout.Check(); err != nil {
		t.Fatalf("Check() after stale failure = %v, want nil", err)
	}

	after := lockout.Snapshot()
	if after.Generation != reset.Generation {
		t.Errorf("late response changed generation: got %d, want %d", after.Generation, reset.Generation)
	}
	if after.Policy != policy {
		t.Errorf("late response restored old policy: got %+v, want %+v", after.Policy, policy)
	}
	if after.FailedTries != 0 {
		t.Errorf("late response restored old failed count: got %d, want 0", after.FailedTries)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	loaded := restarted.Snapshot()
	if loaded.Generation != reset.Generation || loaded.FailedTries != 0 || loaded.Policy != policy {
		t.Errorf("restarted state = %+v, want generation=%d failed=0 policy=%+v",
			loaded, reset.Generation, policy)
	}
}

func TestLockoutResetSupersedesConcurrentFailureAndPolicyChange(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
	store := NewMemoryLockoutStore()
	oldPolicy := DictionaryAttackPolicy{MaxTries: 3}
	newPolicy := DictionaryAttackPolicy{MaxTries: 7}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, oldPolicy, opts)

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	if got := lockout.Snapshot().FailedTries; got != 1 {
		t.Fatalf("FailedTries after first failure = %d, want 1", got)
	}

	// This attempt was authorized against the old count and the old policy.
	late := mustBeginLockoutAttempt(t, lockout)

	reset, err := lockout.Reset([]byte("lockout"))
	if err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	configured, err := lockout.Configure(newPolicy, []byte("lockout"))
	if err != nil {
		t.Fatalf("Configure() = %v", err)
	}
	if configured.Policy != newPolicy {
		t.Fatalf("Configure policy = %+v, want %+v", configured.Policy, newPolicy)
	}

	// A caller may legitimately retry before the late response arrives.
	if err := lockout.Check(); err != nil {
		t.Fatalf("Check() after reset/configure = %v, want nil", err)
	}

	if err := late.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("late Fail() = %v, want ErrStaleLockoutResponse", err)
	}

	// The stale response must not write back the old count or old policy.
	state := lockout.Snapshot()
	if state.Generation != reset.Generation {
		t.Errorf("stale response changed generation: got %d, want %d", state.Generation, reset.Generation)
	}
	if state.Policy != newPolicy {
		t.Errorf("stale response restored old policy: got %+v, want %+v", state.Policy, newPolicy)
	}
	if state.FailedTries != 0 || state.Reserved != 0 {
		t.Errorf("stale response restored old budget: failed=%d reserved=%d, want 0/0",
			state.FailedTries, state.Reserved)
	}

	// A new attempt belongs to the new transaction generation and is accounted
	// only against the new policy.
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	state = lockout.Snapshot()
	if state.FailedTries != 1 || state.Policy != newPolicy {
		t.Errorf("state after new failure = %+v, want failed=1 policy=%+v", state, newPolicy)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	loaded := restarted.Snapshot()
	if loaded.Generation != reset.Generation || loaded.FailedTries != 1 || loaded.Policy != newPolicy {
		t.Errorf("restarted state = %+v, want generation=%d failed=1 policy=%+v",
			loaded, reset.Generation, newPolicy)
	}
}

func TestLockoutConcurrentLateFailuresCannotWriteBackOldPolicy(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 2, 4, 5, 6, 7, 0, time.UTC))
	store := NewMemoryLockoutStore()
	oldPolicy := DictionaryAttackPolicy{MaxTries: 4}
	newPolicy := DictionaryAttackPolicy{MaxTries: 8}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, oldPolicy, opts)

	const attempts = 4
	attemptCh := make(chan *LockoutAttempt, attempts)
	errCh := make(chan error, attempts)
	start := make(chan struct{})
	var beginWG sync.WaitGroup
	for i := 0; i < attempts; i++ {
		beginWG.Add(1)
		go func() {
			defer beginWG.Done()
			<-start
			attempt, err := lockout.Begin()
			if err != nil {
				errCh <- err
				return
			}
			attemptCh <- attempt
		}()
	}
	close(start)
	beginWG.Wait()
	close(attemptCh)
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent Begin() = %v", err)
	}
	late := make([]*LockoutAttempt, 0, attempts)
	for attempt := range attemptCh {
		late = append(late, attempt)
	}
	if len(late) != attempts {
		t.Fatalf("reserved %d attempts, want %d", len(late), attempts)
	}

	reset, err := lockout.Reset([]byte("lockout"))
	if err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	if _, err := lockout.Configure(newPolicy, []byte("lockout")); err != nil {
		t.Fatalf("Configure() = %v", err)
	}

	var failWG sync.WaitGroup
	lateErrs := make(chan error, attempts)
	for _, attempt := range late {
		failWG.Add(1)
		go func(attempt *LockoutAttempt) {
			defer failWG.Done()
			lateErrs <- attempt.Fail()
		}(attempt)
	}
	failWG.Wait()
	close(lateErrs)

	for err := range lateErrs {
		if !errors.Is(err, ErrStaleLockoutResponse) {
			t.Errorf("late Fail() = %v, want ErrStaleLockoutResponse", err)
		}
	}

	state := lockout.Snapshot()
	if state.Generation != reset.Generation {
		t.Errorf("Generation = %d, want %d", state.Generation, reset.Generation)
	}
	if state.Policy != newPolicy {
		t.Errorf("Policy = %+v, want %+v", state.Policy, newPolicy)
	}
	if state.FailedTries != 0 || state.Reserved != 0 {
		t.Errorf("late failures changed budget: failed=%d reserved=%d, want 0/0",
			state.FailedTries, state.Reserved)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	loaded := restarted.Snapshot()
	if loaded.Generation != reset.Generation || loaded.Policy != newPolicy || loaded.FailedTries != 0 {
		t.Errorf("restarted state = %+v, want generation=%d policy=%+v failed=0",
			loaded, reset.Generation, newPolicy)
	}
}

func TestLockoutInvalidParametersFailClosed(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))

	t.Run("PolicyExceedsLimits", func(t *testing.T) {
		store := NewMemoryLockoutStore()
		_, err := NewLockout(store,
			DictionaryAttackPolicy{MaxTries: 5},
			LockoutOptions{
				Limits: LockoutLimits{MaxTries: 4},
				Now:    clock.Now,
			})
		if !errors.Is(err, ErrInvalidLockoutParameters) {
			t.Fatalf("NewLockout() = %v, want ErrInvalidLockoutParameters", err)
		}
		if data := store.Bytes(); data != nil {
			t.Errorf("invalid initial policy was persisted: %q", data)
		}
	})

	t.Run("AuthorizationTooLarge", func(t *testing.T) {
		store := NewMemoryLockoutStore()
		_, err := NewLockout(store,
			DictionaryAttackPolicy{MaxTries: 1},
			LockoutOptions{
				LockoutAuth: make([]byte, MaxLockoutAuthSize+1),
				Now:         clock.Now,
			})
		if !errors.Is(err, ErrInvalidLockoutParameters) {
			t.Fatalf("NewLockout() = %v, want ErrInvalidLockoutParameters", err)
		}
		if data := store.Bytes(); data != nil {
			t.Errorf("manager with invalid auth was persisted: %q", data)
		}
	})

	t.Run("InvalidConfigureKeepsProtection", func(t *testing.T) {
		store := NewMemoryLockoutStore()
		lockout := mustNewLockout(t, store,
			DictionaryAttackPolicy{MaxTries: 1},
			LockoutOptions{
				LockoutAuth: []byte("lockout"),
				Limits:      LockoutLimits{MaxTries: 4},
				Now:         clock.Now,
			})
		mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
		if err := lockout.Check(); !errors.Is(err, ErrLockout) {
			t.Fatalf("Check() = %v, want ErrLockout", err)
		}

		if _, err := lockout.Configure(DictionaryAttackPolicy{MaxTries: 5}, []byte("lockout")); !errors.Is(err, ErrInvalidLockoutParameters) {
			t.Fatalf("Configure() = %v, want ErrInvalidLockoutParameters", err)
		}
		state := lockout.Snapshot()
		if state.Policy.MaxTries != 1 || state.FailedTries != 1 || !state.LockedOut() {
			t.Errorf("invalid Configure changed protection: %+v", state)
		}

		if _, err := lockout.Configure(DictionaryAttackPolicy{MaxTries: 2}, []byte("wrong")); !errors.Is(err, ErrLockoutAuthFailed) {
			t.Fatalf("Configure(wrong auth) = %v, want ErrLockoutAuthFailed", err)
		}
		state = lockout.Snapshot()
		if state.Policy.MaxTries != 1 || state.FailedTries != 1 || !state.LockedOut() {
			t.Errorf("failed lockout auth changed protection: %+v", state)
		}
	})

	t.Run("CorruptStateIsNotReplaced", func(t *testing.T) {
		store := NewMemoryLockoutStore()
		corrupt := []byte("{")
		if err := store.Save(corrupt); err != nil {
			t.Fatalf("Save() = %v", err)
		}
		_, err := NewLockout(store, DictionaryAttackPolicy{MaxTries: 1}, LockoutOptions{Now: clock.Now})
		if !errors.Is(err, ErrLockoutStateCorrupt) {
			t.Fatalf("NewLockout(corrupt) = %v, want ErrLockoutStateCorrupt", err)
		}
		if got := store.Bytes(); !bytes.Equal(got, corrupt) {
			t.Errorf("corrupt state was overwritten: got %q, want %q", got, corrupt)
		}
	})

	t.Run("TamperedChecksumIsRejected", func(t *testing.T) {
		clock := newLockoutTestClock(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
		store := NewMemoryLockoutStore()
		_ = mustNewLockout(t, store,
			DictionaryAttackPolicy{MaxTries: 3},
			LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

		data := store.Bytes()
		tampered := bytes.Replace(data, []byte(`"maxTries":3`), []byte(`"maxTries":9`), 1)
		if bytes.Equal(tampered, data) {
			t.Fatal("could not tamper with persisted state for test")
		}
		if err := store.Save(tampered); err != nil {
			t.Fatalf("Save() = %v", err)
		}
		_, err := NewLockout(store,
			DictionaryAttackPolicy{MaxTries: 1},
			LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
		if !errors.Is(err, ErrLockoutStateCorrupt) {
			t.Fatalf("NewLockout(tampered) = %v, want ErrLockoutStateCorrupt", err)
		}
	})
}

func TestLockoutPersistenceFailureDoesNotPublishTransition(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 3, 5, 6, 7, 8, 0, time.UTC))
	store := &lockoutFailStore{inner: NewMemoryLockoutStore()}
	oldPolicy := DictionaryAttackPolicy{MaxTries: 2}
	newPolicy := DictionaryAttackPolicy{MaxTries: 9}
	lockout := mustNewLockout(t, store, oldPolicy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	before := lockout.Snapshot()

	store.SetFail(true)
	if _, err := lockout.Configure(newPolicy, []byte("lockout")); !errors.Is(err, ErrLockoutPersistence) {
		t.Fatalf("Configure() with failing store = %v, want ErrLockoutPersistence", err)
	}
	if _, err := lockout.Reset([]byte("lockout")); !errors.Is(err, ErrLockoutPersistence) {
		t.Fatalf("Reset() with failing store = %v, want ErrLockoutPersistence", err)
	}
	if _, err := lockout.Begin(); !errors.Is(err, ErrLockoutPersistence) {
		t.Fatalf("Begin() with failing store = %v, want ErrLockoutPersistence", err)
	}

	state := lockout.Snapshot()
	if state.Generation != before.Generation ||
		state.Epoch != before.Epoch ||
		state.Revision != before.Revision ||
		state.Policy != before.Policy ||
		state.FailedTries != before.FailedTries ||
		state.Reserved != before.Reserved {
		t.Errorf("failed persistence published a transition: got %+v, want %+v", state, before)
	}

	// The guard remains usable after the storage recovers, but begins from the
	// last committed state.
	store.SetFail(false)
	if _, err := lockout.Begin(); err != nil {
		t.Fatalf("Begin() after storage recovery = %v", err)
	}
	state = lockout.Snapshot()
	if state.Policy != oldPolicy || state.Reserved != 1 {
		t.Errorf("state after storage recovery = %+v, want old policy and one reservation", state)
	}
}

func TestLockoutAuthRecoveryAndOwnerRecovery(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 2, LockoutRecovery: 10}
	opts := LockoutOptions{
		LockoutAuth: []byte("lockout"),
		OwnerAuth:   []byte("owner"),
		Now:         clock.Now,
	}
	lockout := mustNewLockout(t, store, policy, opts)

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	if !lockout.Snapshot().LockedOut() {
		t.Fatal("guard is not locked after maxTries failures")
	}

	if _, err := lockout.Reset([]byte("wrong")); !errors.Is(err, ErrLockoutAuthFailed) {
		t.Fatalf("Reset(wrong) = %v, want ErrLockoutAuthFailed", err)
	}
	state := lockout.Snapshot()
	if state.LockoutAuthFailures != 1 {
		t.Errorf("LockoutAuthFailures = %d, want 1", state.LockoutAuthFailures)
	}
	if state.LockoutAuthBlockedUntil.IsZero() {
		t.Error("lockout auth failure did not start a recovery interval")
	}

	if _, err := lockout.Reset([]byte("lockout")); !errors.Is(err, ErrLockoutAuthRecovery) {
		t.Fatalf("Reset() during recovery = %v, want ErrLockoutAuthRecovery", err)
	}
	if err := lockout.Check(); !errors.Is(err, ErrLockout) {
		t.Fatalf("Check() during auth recovery = %v, want ErrLockout", err)
	}

	clock.Advance(10 * time.Second)
	state, err := lockout.Reset([]byte("lockout"))
	if err != nil {
		t.Fatalf("Reset() after recovery = %v", err)
	}
	if state.FailedTries != 0 || state.LockoutAuthFailures != 0 {
		t.Errorf("Reset() left failed=%d authFailures=%d, want 0/0",
			state.FailedTries, state.LockoutAuthFailures)
	}

	// Lock the guard again and prove owner recovery is an independent path
	// that preserves the configured policy.
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	if _, err := lockout.OwnerRecover([]byte("wrong")); !errors.Is(err, ErrOwnerAuthFailed) {
		t.Fatalf("OwnerRecover(wrong) = %v, want ErrOwnerAuthFailed", err)
	}
	if !lockout.Snapshot().LockedOut() {
		t.Error("failed owner recovery cleared lockout")
	}
	state, err = lockout.OwnerRecover([]byte("owner"))
	if err != nil {
		t.Fatalf("OwnerRecover() = %v", err)
	}
	if state.FailedTries != 0 || state.LockedOut() {
		t.Errorf("OwnerRecover left failed=%d locked=%v, want 0/false",
			state.FailedTries, state.LockedOut())
	}
	if state.Policy != policy {
		t.Errorf("OwnerRecover changed policy: got %+v, want %+v", state.Policy, policy)
	}

	disabled := mustNewLockout(t, NewMemoryLockoutStore(), policy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	if _, err := disabled.OwnerRecover(nil); !errors.Is(err, ErrOwnerRecoveryDisabled) {
		t.Fatalf("OwnerRecover() with no owner configured = %v, want ErrOwnerRecoveryDisabled", err)
	}
}

func TestLockoutConfigurePreservesExistingProtection(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 4, 6, 7, 8, 9, 0, time.UTC))
	store := NewMemoryLockoutStore()
	opts := LockoutOptions{
		LockoutAuth: []byte("lockout"),
		OwnerAuth:   []byte("owner"),
		Now:         clock.Now,
	}
	lockout := mustNewLockout(t, store, DictionaryAttackPolicy{MaxTries: 3}, opts)

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	before := lockout.Snapshot()
	if before.FailedTries != 2 || before.LockedOut() {
		t.Fatalf("state before Configure = %+v, want failed=2 and unlocked", before)
	}

	morePermissive := DictionaryAttackPolicy{MaxTries: 5}
	state, err := lockout.Configure(morePermissive, []byte("lockout"))
	if err != nil {
		t.Fatalf("Configure() = %v", err)
	}
	if state.FailedTries != before.FailedTries {
		t.Errorf("Configure reset failed count: got %d, want %d", state.FailedTries, before.FailedTries)
	}
	if !state.LastFailure.Equal(before.LastFailure) {
		t.Errorf("Configure changed last failure time: got %v, want %v",
			state.LastFailure, before.LastFailure)
	}
	if state.LockedOut() {
		t.Error("more permissive Configure left guard locked")
	}

	// Lowering maxTries below the existing failed count must preserve the
	// protection state and fail closed.
	lessPermissive := DictionaryAttackPolicy{MaxTries: 2}
	state, err = lockout.Configure(lessPermissive, []byte("lockout"))
	if err != nil {
		t.Fatalf("Configure() = %v", err)
	}
	if state.FailedTries != 2 || !state.LockedOut() {
		t.Errorf("lower maxTries state = %+v, want failed=2 and locked", state)
	}

	state, err = lockout.OwnerRecover([]byte("owner"))
	if err != nil {
		t.Fatalf("OwnerRecover() = %v", err)
	}
	if state.FailedTries != 0 || state.Policy != lessPermissive || state.LockedOut() {
		t.Errorf("OwnerRecover state = %+v, want failed=0 policy=%+v", state, lessPermissive)
	}
}

func TestLockoutRecoveryTimeAndBoundaries(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC))
	policy := DictionaryAttackPolicy{MaxTries: 2, RecoveryTime: 5}
	lockout := mustNewLockout(t, NewMemoryLockoutStore(), policy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	if !lockout.Snapshot().LockedOut() {
		t.Fatal("guard is not locked after maxTries failures")
	}

	clock.Advance(5 * time.Second)
	state := lockout.Snapshot()
	if state.FailedTries != 1 || state.LockedOut() {
		t.Errorf("after one recovery interval = %+v, want failed=1 and unlocked", state)
	}
	if err := lockout.Check(); err != nil {
		t.Fatalf("Check() after one recovery interval = %v, want nil", err)
	}

	clock.Advance(5 * time.Second)
	state = lockout.Snapshot()
	if state.FailedTries != 0 || !state.LastFailure.IsZero() {
		t.Errorf("after two recovery intervals = %+v, want failed=0", state)
	}

	// Every uint32 policy value is representable by the TPM, including the
	// maximum values. The guard must accept those boundaries.
	maxPolicy := DictionaryAttackPolicy{
		MaxTries:        math.MaxUint32,
		RecoveryTime:    math.MaxUint32,
		LockoutRecovery: math.MaxUint32,
	}
	maxLockout := mustNewLockout(t, NewMemoryLockoutStore(), maxPolicy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	if got := maxLockout.Snapshot().Policy; got != maxPolicy {
		t.Errorf("boundary policy = %+v, want %+v", got, maxPolicy)
	}

	exactLimit := mustNewLockout(t, NewMemoryLockoutStore(),
		DictionaryAttackPolicy{MaxTries: 5, RecoveryTime: 10, LockoutRecovery: 10},
		LockoutOptions{
			Limits: LockoutLimits{MaxTries: 5, RecoveryTime: 10, LockoutRecovery: 10},
			Now:    clock.Now,
		})
	if got := exactLimit.Snapshot().Policy.MaxTries; got != 5 {
		t.Errorf("policy at exact limit = %d, want 5", got)
	}

	// A zero maxTries is accepted for TPM compatibility but is fail-closed for
	// this guard: there is no failure budget in which to authorize.
	zero := mustNewLockout(t, NewMemoryLockoutStore(), DictionaryAttackPolicy{},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	if !zero.Snapshot().LockedOut() {
		t.Error("zero maxTries policy did not fail closed")
	}
	if _, err := zero.Begin(); !errors.Is(err, ErrLockout) {
		t.Fatalf("Begin() with zero maxTries = %v, want ErrLockout", err)
	}
}

func TestLockoutReservationsPreventConcurrentOverrun(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 2}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, policy, opts)

	first := mustBeginLockoutAttempt(t, lockout)
	second := mustBeginLockoutAttempt(t, lockout)
	if _, err := lockout.Begin(); !errors.Is(err, ErrLockout) {
		t.Fatalf("third Begin() = %v, want ErrLockout", err)
	}
	if state := lockout.Snapshot(); state.Reserved != 2 {
		t.Errorf("Reserved = %d, want 2", state.Reserved)
	}

	mustFailLockoutAttempt(t, first)
	if state := lockout.Snapshot(); state.FailedTries != 1 || state.Reserved != 1 {
		t.Errorf("after first result: failed=%d reserved=%d, want 1/1",
			state.FailedTries, state.Reserved)
	}
	mustFailLockoutAttempt(t, second)
	state := lockout.Snapshot()
	if state.FailedTries != 2 || state.Reserved != 0 || !state.LockedOut() {
		t.Errorf("after both results = %+v, want failed=2 reserved=0 locked", state)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	if got := restarted.Snapshot(); got.FailedTries != 2 || !got.LockedOut() {
		t.Errorf("restarted state = %+v, want failed=2 locked", got)
	}
}

func TestLockoutRestartChargesInFlightReservations(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 6, 8, 9, 10, 11, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 3}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	first := mustNewLockout(t, store, policy, opts)

	_ = mustBeginLockoutAttempt(t, first)
	if state := first.Snapshot(); state.Reserved != 1 {
		t.Fatalf("Reserved before restart = %d, want 1", state.Reserved)
	}

	// The process stops before the authorization result is known. The restart
	// must charge the reservation as a failure rather than silently restoring
	// the whole failure budget.
	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	state := restarted.Snapshot()
	if state.FailedTries != 1 || state.Reserved != 0 {
		t.Errorf("restarted state = %+v, want failed=1 reserved=0", state)
	}
}

func TestLockoutFileStoreSurvivesRestart(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC))
	dir := t.TempDir()
	path := filepath.Join(dir, "lockout-state.json")
	store, err := NewFileLockoutStore(path)
	if err != nil {
		t.Fatalf("NewFileLockoutStore() = %v", err)
	}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, DictionaryAttackPolicy{MaxTries: 3}, opts)

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	reset, err := lockout.Reset([]byte("lockout"))
	if err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	newPolicy := DictionaryAttackPolicy{MaxTries: 7, RecoveryTime: 30, LockoutRecovery: 30}
	if _, err := lockout.Configure(newPolicy, []byte("lockout")); err != nil {
		t.Fatalf("Configure() = %v", err)
	}
	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	state := restarted.Snapshot()
	if state.Generation != reset.Generation {
		t.Errorf("Generation = %d, want %d", state.Generation, reset.Generation)
	}
	if state.FailedTries != 1 || state.Policy != newPolicy {
		t.Errorf("restarted state = %+v, want failed=1 policy=%+v", state, newPolicy)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("lockout state file is empty")
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".lockout-state.json.tmp-*"))
	if err != nil {
		t.Fatalf("Glob() = %v", err)
	}
	if len(temps) != 0 {
		t.Errorf("temporary state files were left behind: %v", temps)
	}
}

func TestLockoutAttemptCannotCommitTwice(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC))
	lockout := mustNewLockout(t, NewMemoryLockoutStore(),
		DictionaryAttackPolicy{MaxTries: 2},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	attempt := mustBeginLockoutAttempt(t, lockout)

	if err := attempt.Succeed(); err != nil {
		t.Fatalf("Succeed() = %v", err)
	}
	if err := attempt.Succeed(); !errors.Is(err, ErrLockoutAttemptCommitted) {
		t.Fatalf("second Succeed() = %v, want ErrLockoutAttemptCommitted", err)
	}
	if state := lockout.Snapshot(); state.FailedTries != 0 || state.Reserved != 0 {
		t.Errorf("successful attempt left state %+v, want failed=0 reserved=0", state)
	}
}

func TestDictionaryAttackPolicyCommand(t *testing.T) {
	policy := DictionaryAttackPolicy{MaxTries: 5, RecoveryTime: 10, LockoutRecovery: 20}
	cmd, err := policy.Command(AuthHandle{Handle: TPMRHLockout})
	if err != nil {
		t.Fatalf("Command() = %v", err)
	}
	if cmd.AuthHandle.Handle != TPMRHLockout ||
		cmd.MaxTries != policy.MaxTries ||
		cmd.RecoveryTime != policy.RecoveryTime ||
		cmd.LockoutRecovery != policy.LockoutRecovery {
		t.Errorf("Command() = %+v, want policy %+v for TPM_RH_LOCKOUT", cmd, policy)
	}

	if _, err := policy.Command(AuthHandle{Handle: TPMRHOwner}); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Fatalf("Command(TPM_RH_OWNER) = %v, want ErrInvalidLockoutParameters", err)
	}

	reset, err := DictionaryAttackResetCommand(AuthHandle{Handle: TPMRHLockout})
	if err != nil {
		t.Fatalf("DictionaryAttackResetCommand() = %v", err)
	}
	if reset.LockHandle.HandleValue() != TPMRHLockout.HandleValue() {
		t.Errorf("reset LockHandle = %#x, want TPM_RH_LOCKOUT", reset.LockHandle.HandleValue())
	}
	if _, err := DictionaryAttackResetCommand(AuthHandle{Handle: TPMRHOwner}); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Fatalf("DictionaryAttackResetCommand(TPM_RH_OWNER) = %v, want ErrInvalidLockoutParameters", err)
	}
}
