package tpm2

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type lockoutStepFailStore struct {
	inner *MemoryLockoutStore

	mu       sync.Mutex
	failSave int
	saves    int
}

func (s *lockoutStepFailStore) Load() ([]byte, error) {
	return s.inner.Load()
}

func (s *lockoutStepFailStore) Save(data []byte) error {
	s.mu.Lock()
	s.saves++
	fail := s.failSave != 0 && s.saves == s.failSave
	s.mu.Unlock()
	if fail {
		return errors.New("injected lockout persistence failure")
	}
	return s.inner.Save(data)
}

func (s *lockoutStepFailStore) SetFailAt(save int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failSave = save
}

func TestLockoutConfigureWithRunnerInvalidatesLateFailure(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 1, 2, 3, 4, 0, time.UTC))
	store := NewMemoryLockoutStore()
	oldPolicy := DictionaryAttackPolicy{MaxTries: 4}
	newPolicy := DictionaryAttackPolicy{MaxTries: 8}
	lockout := mustNewLockout(t, store, oldPolicy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	late := mustBeginLockoutAttempt(t, lockout)
	before := lockout.Snapshot()
	state, err := lockout.ConfigureWithRunner(newPolicy, []byte("lockout"), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("ConfigureWithRunner() = %v", err)
	}
	if state.Policy != newPolicy {
		t.Errorf("policy = %+v, want %+v", state.Policy, newPolicy)
	}
	if state.Epoch != before.Epoch+1 {
		t.Errorf("epoch = %d, want %d", state.Epoch, before.Epoch+1)
	}
	// The outstanding attempt was charged as a failure when the policy
	// changed, so changing policy never releases reserved budget.
	if state.FailedTries != 1 || state.Reserved != 0 {
		t.Errorf("state after configure = failed:%d reserved:%d, want 1/0",
			state.FailedTries, state.Reserved)
	}
	if err := late.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("late Fail() = %v, want ErrStaleLockoutResponse", err)
	}
	after := lockout.Snapshot()
	if after.FailedTries != 1 || after.Policy != newPolicy || after.InDoubt() {
		t.Errorf("late failure changed state: %+v", after)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	loaded := restarted.Snapshot()
	if loaded.Policy != newPolicy || loaded.FailedTries != 1 || loaded.InDoubt() {
		t.Errorf("restarted state = %+v, want policy=%+v failed=1", loaded, newPolicy)
	}
}

func TestLockoutConfigureChargesReservations(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 1, 4, 5, 6, 0, time.UTC))
	store := NewMemoryLockoutStore()
	lockout := mustNewLockout(t, store,
		DictionaryAttackPolicy{MaxTries: 4},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	first := mustBeginLockoutAttempt(t, lockout)
	second := mustBeginLockoutAttempt(t, lockout)
	state, err := lockout.Configure(DictionaryAttackPolicy{MaxTries: 2}, []byte("lockout"))
	if err != nil {
		t.Fatalf("Configure() = %v", err)
	}
	if state.FailedTries != 2 || state.Reserved != 0 || !state.LockedOut() {
		t.Fatalf("Configure() state = %+v, want failed=2 reserved=0 locked", state)
	}
	if err := first.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("first late Fail() = %v, want ErrStaleLockoutResponse", err)
	}
	if err := second.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("second late Fail() = %v, want ErrStaleLockoutResponse", err)
	}
	if got := lockout.Snapshot(); got.FailedTries != 2 || !got.LockedOut() {
		t.Errorf("late failures changed state: %+v", got)
	}
}

func TestLockoutResetWithRunnerIsAtomicWithLateFailure(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 2, 3, 4, 5, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 3, RecoveryTime: 30, LockoutRecovery: 30}
	lockout := mustNewLockout(t, store, policy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	late := mustBeginLockoutAttempt(t, lockout)
	before := lockout.Snapshot()
	state, err := lockout.ResetWithRunner([]byte("lockout"), func() error {
		if !lockout.Snapshot().InDoubt() {
			t.Error("write-ahead intent was not visible before the TPM command")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ResetWithRunner() = %v", err)
	}
	if state.Generation != before.Generation+1 {
		t.Errorf("generation = %d, want %d", state.Generation, before.Generation+1)
	}
	if state.FailedTries != 0 || state.Reserved != 0 || state.InDoubt() {
		t.Errorf("reset state = %+v, want empty and committed", state)
	}
	if err := late.Fail(); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("late Fail() = %v, want ErrStaleLockoutResponse", err)
	}
	if got := lockout.Snapshot(); got.FailedTries != 0 || got.Policy != policy {
		t.Errorf("late failure restored old state: %+v", got)
	}

	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	loaded := restarted.Snapshot()
	if loaded.Generation != state.Generation || loaded.FailedTries != 0 ||
		loaded.Policy != policy || loaded.InDoubt() {
		t.Errorf("restarted state = %+v", loaded)
	}
}

func TestLockoutRunnerFailureKeepsOldProtection(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 3, 4, 5, 6, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 3}
	lockout := mustNewLockout(t, store, policy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	mustFailLockoutAttempt(t, mustBeginLockoutAttempt(t, lockout))
	late := mustBeginLockoutAttempt(t, lockout)
	before := lockout.Snapshot()
	runnerErr := errors.New("tpm command failed")
	if _, err := lockout.ResetWithRunner([]byte("lockout"), func() error {
		return runnerErr
	}); !errors.Is(err, runnerErr) {
		t.Fatalf("ResetWithRunner() = %v, want %v", err, runnerErr)
	}
	after := lockout.Snapshot()
	if after.Generation != before.Generation ||
		after.Epoch != before.Epoch ||
		after.Policy != before.Policy ||
		after.FailedTries != before.FailedTries ||
		after.Reserved != before.Reserved ||
		after.InDoubt() {
		t.Errorf("failed runner changed state: got %+v, want %+v", after, before)
	}
	// The attempt belonged to the still-current generation and can commit.
	if err := late.Fail(); err != nil {
		t.Fatalf("late Fail() = %v", err)
	}
	if got := lockout.Snapshot().FailedTries; got != 2 {
		t.Errorf("FailedTries = %d, want 2", got)
	}
}

func TestLockoutTPMAuthFailureStartsRecovery(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 4, 5, 6, 7, 0, time.UTC))
	store := NewMemoryLockoutStore()
	policy := DictionaryAttackPolicy{MaxTries: 3, LockoutRecovery: 10}
	lockout := mustNewLockout(t, store, policy,
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})

	state, err := lockout.ResetWithRunner([]byte("lockout"), func() error {
		return TPMRCAuthFail
	})
	if !errors.Is(err, TPMRCAuthFail) {
		t.Fatalf("ResetWithRunner() = %v, want TPM_RC_AUTH_FAIL", err)
	}
	if !errors.Is(err, ErrLockoutAuthFailed) {
		t.Fatalf("ResetWithRunner() = %v, want ErrLockoutAuthFailed evidence", err)
	}
	var lockoutErr *LockoutError
	if !errors.As(err, &lockoutErr) {
		t.Fatalf("ResetWithRunner() = %v, want *LockoutError", err)
	}
	if lockoutErr.Response != TPMRCAuthFail ||
		lockoutErr.Stage != LockoutStageTPM ||
		lockoutErr.Hierarchy != TPMRHLockout {
		t.Errorf("lockout error evidence = %+v", lockoutErr)
	}
	if state.LockoutAuthFailures != 1 || state.LockoutAuthBlockedUntil.IsZero() {
		t.Errorf("auth failure state = %+v", state)
	}
	if state.Pending != nil {
		t.Errorf("auth failure left pending transaction: %+v", state.Pending)
	}
	if _, err := lockout.Reset([]byte("lockout")); !errors.Is(err, ErrLockoutAuthRecovery) {
		t.Fatalf("Reset() during recovery = %v, want ErrLockoutAuthRecovery", err)
	}
}

func TestLockoutInDoubtPersistsFailClosedAndOwnerRecovers(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 5, 6, 7, 8, 0, time.UTC))
	store := &lockoutStepFailStore{inner: NewMemoryLockoutStore()}
	policy := DictionaryAttackPolicy{MaxTries: 3, RecoveryTime: 30, LockoutRecovery: 30}
	opts := LockoutOptions{
		LockoutAuth: []byte("lockout"),
		OwnerAuth:   []byte("owner"),
		Now:         clock.Now,
	}
	lockout := mustNewLockout(t, store, policy, opts)

	// NewLockout used save 1. ResetWithRunner persists its intent with save 2
	// and fails to publish the final generation with save 3.
	store.SetFailAt(3)
	if _, err := lockout.ResetWithRunner([]byte("lockout"), func() error {
		return nil
	}); !errors.Is(err, ErrLockoutPersistence) {
		t.Fatalf("ResetWithRunner() = %v, want ErrLockoutPersistence", err)
	}
	if state := lockout.Snapshot(); !state.InDoubt() {
		t.Fatalf("state after failed commit = %+v, want in-doubt", state)
	}
	if err := lockout.Check(); !errors.Is(err, ErrLockoutInDoubt) {
		t.Fatalf("Check() = %v, want ErrLockoutInDoubt", err)
	}
	if err := lockout.Check(); !errors.Is(err, ErrLockout) {
		t.Fatalf("Check() = %v, want ErrLockout evidence", err)
	}
	if _, err := lockout.Begin(); !errors.Is(err, ErrLockoutInDoubt) {
		t.Fatalf("Begin() = %v, want ErrLockoutInDoubt", err)
	}

	// A restart must observe the same in-doubt record, not the old policy.
	store.SetFailAt(0)
	restarted := mustNewLockout(t, store, DictionaryAttackPolicy{}, opts)
	loaded := restarted.Snapshot()
	if !loaded.InDoubt() {
		t.Fatalf("restarted state = %+v, want in-doubt", loaded)
	}
	if loaded.Pending == nil || loaded.Pending.Stage != LockoutStageReset {
		t.Errorf("restarted pending = %+v, want reset intent", loaded.Pending)
	}
	if loaded.Policy != policy {
		t.Errorf("restarted policy = %+v, want %+v", loaded.Policy, policy)
	}

	state, err := restarted.OwnerRecover([]byte("owner"))
	if err != nil {
		t.Fatalf("OwnerRecover() = %v", err)
	}
	if state.InDoubt() || state.FailedTries != 0 || state.Policy != policy {
		t.Errorf("state after owner recovery = %+v", state)
	}
	if err := restarted.Check(); err != nil {
		t.Errorf("Check() after owner recovery = %v", err)
	}
}

func TestLockoutPreparePersistenceFailureSkipsTPMCommand(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 6, 1, 2, 3, 0, time.UTC))
	store := &lockoutStepFailStore{inner: NewMemoryLockoutStore()}
	policy := DictionaryAttackPolicy{MaxTries: 3}
	opts := LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now}
	lockout := mustNewLockout(t, store, policy, opts)
	before := lockout.Snapshot()

	// NewLockout used save 1. The write-ahead intent for Reset is save 2.
	store.SetFailAt(2)
	called := false
	if _, err := lockout.ResetWithRunner([]byte("lockout"), func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrLockoutPersistence) {
		t.Fatalf("ResetWithRunner() = %v, want ErrLockoutPersistence", err)
	}
	if called {
		t.Fatal("TPM command ran after the write-ahead intent failed")
	}
	after := lockout.Snapshot()
	if after.Generation != before.Generation ||
		after.Epoch != before.Epoch ||
		after.FailedTries != before.FailedTries ||
		after.Reserved != before.Reserved ||
		after.InDoubt() {
		t.Errorf("failed prepare changed state: got %+v, want %+v", after, before)
	}
}

func TestLockoutTransactionRejectsNilTransport(t *testing.T) {
	if _, err := NewLockoutTransaction(nil, NewMemoryLockoutStore(), DictionaryAttackPolicy{}, LockoutOptions{}); !errors.Is(err, ErrNilLockoutTPM) {
		t.Fatalf("NewLockoutTransaction(nil) = %v, want ErrNilLockoutTPM", err)
	}
}

func TestLockoutBoundHMACSessionRejectsStaleResponse(t *testing.T) {
	clock := newLockoutTestClock(time.Date(2026, 9, 6, 7, 8, 9, 0, time.UTC))
	lockout := mustNewLockout(t, NewMemoryLockoutStore(),
		DictionaryAttackPolicy{MaxTries: 2},
		LockoutOptions{LockoutAuth: []byte("lockout"), Now: clock.Now})
	attempt := mustBeginLockoutAttempt(t, lockout)

	session := &hmacSession{sessionOptions: defaultOptions()}
	session.lockoutAttempt = attempt
	if _, err := lockout.Reset([]byte("lockout")); err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	if err := session.Validate(TPMRCSuccess, 0, nil, nil, 0, nil); !errors.Is(err, ErrStaleLockoutResponse) {
		t.Fatalf("Validate() = %v, want ErrStaleLockoutResponse", err)
	}
}
