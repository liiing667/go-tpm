package tpm2

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// MaxLockoutAuthSize is the largest authorization value accepted by the
// dictionary-attack guard. TPM2B_AUTH values are bounded by the largest TPM
// digest, which is 64 bytes.
const MaxLockoutAuthSize = 64

var (
	// ErrNoLockoutState is returned by a LockoutStore when no state has been
	// committed yet. It is not an error condition.
	ErrNoLockoutState = errors.New("tpm2: no persisted lockout state")
	// ErrNilLockoutStore indicates that a lockout guard was created without a
	// persistence backend.
	ErrNilLockoutStore = errors.New("tpm2: nil lockout store")
	// ErrInvalidLockoutParameters indicates that a policy, authorization value,
	// or persisted field cannot be used safely.
	ErrInvalidLockoutParameters = errors.New("tpm2: invalid dictionary attack parameters")
	// ErrInvalidLockoutState indicates that the in-memory lockout state is
	// internally inconsistent.
	ErrInvalidLockoutState = errors.New("tpm2: invalid lockout state")
	// ErrLockoutStateCorrupt indicates that persisted state failed validation.
	// A corrupt state is never silently replaced by a default state.
	ErrLockoutStateCorrupt = errors.New("tpm2: corrupt persisted lockout state")
	// ErrLockoutPersistence indicates that a state transition could not be
	// made durable. The requested transition is not published. If a
	// write-ahead intent was already durable, the guard remains in-doubt and
	// fail-closed instead of restoring the previous policy.
	ErrLockoutPersistence = errors.New("tpm2: lockout state could not be persisted")
	// ErrLockout indicates that dictionary-attack protection currently denies
	// authorization attempts.
	ErrLockout = errors.New("tpm2: dictionary attack lockout is active")
	// ErrLockoutAuthFailed indicates that the lockout authorization value did
	// not match.
	ErrLockoutAuthFailed = errors.New("tpm2: lockout authorization failed")
	// ErrLockoutAuthRecovery indicates that the lockout authorization value
	// cannot be presented until its recovery interval expires.
	ErrLockoutAuthRecovery = errors.New("tpm2: lockout authorization is in its recovery interval")
	// ErrOwnerAuthFailed indicates that owner recovery authorization failed.
	ErrOwnerAuthFailed = errors.New("tpm2: owner authorization failed")
	// ErrOwnerRecoveryDisabled indicates that no owner authorization was
	// configured for emergency recovery.
	ErrOwnerRecoveryDisabled = errors.New("tpm2: owner recovery is not configured")
	// ErrStaleLockoutResponse indicates that an authorization response belongs
	// to a reset/configuration generation that has already been superseded.
	ErrStaleLockoutResponse = errors.New("tpm2: stale lockout response")
	// ErrLockoutAttemptCommitted indicates that an attempt was committed twice.
	ErrLockoutAttemptCommitted = errors.New("tpm2: lockout attempt already committed")
	// ErrLockoutCounterExhausted indicates that a monotonic counter used by the
	// transaction can no longer be advanced safely.
	ErrLockoutCounterExhausted = errors.New("tpm2: lockout transaction counter exhausted")
	// ErrLockoutInDoubt indicates that a durable lockout mutation was
	// interrupted. The persisted state intentionally remains fail-closed until
	// an owner recovery explicitly resolves it.
	ErrLockoutInDoubt = errors.New("tpm2: lockout transaction is in doubt")
	// ErrNilLockoutTPM indicates that a lockout transaction was created without
	// a transport for the lockout hierarchy commands.
	ErrNilLockoutTPM = errors.New("tpm2: nil lockout TPM transport")
)

// Aliases kept for callers that describe the condition as an authorization
// transaction rather than a response.
var (
	// ErrLockoutAuth is an alias for ErrLockoutAuthFailed.
	ErrLockoutAuth = ErrLockoutAuthFailed
	// ErrStaleLockoutTransaction is an alias for ErrStaleLockoutResponse.
	ErrStaleLockoutTransaction = ErrStaleLockoutResponse
)

// LockoutStage identifies the part of a lockout transaction that produced an
// error. The stage is retained in LockoutError so a caller can distinguish a
// validation failure from a TPM response or a persistence failure.
type LockoutStage string

const (
	// LockoutStageConstruct covers guard construction and state loading.
	LockoutStageConstruct LockoutStage = "construct"
	// LockoutStageConfigure covers dictionary-attack parameter changes.
	LockoutStageConfigure LockoutStage = "configure"
	// LockoutStageReset covers dictionary-attack lock resets.
	LockoutStageReset LockoutStage = "reset"
	// LockoutStageOwnerRecover covers the owner emergency-recovery path.
	LockoutStageOwnerRecover LockoutStage = "owner-recover"
	// LockoutStageCheck covers admission checks that do not reserve a slot.
	LockoutStageCheck LockoutStage = "check"
	// LockoutStageBegin covers reservation of an authorization attempt.
	LockoutStageBegin LockoutStage = "begin"
	// LockoutStageCommit covers publication of an attempt result.
	LockoutStageCommit LockoutStage = "commit"
	// LockoutStageTPM covers execution of a lockout-hierarchy TPM command.
	LockoutStageTPM LockoutStage = "tpm"
	// LockoutStagePersist covers durable publication of a state transition.
	LockoutStagePersist LockoutStage = "persist"
)

// LockoutError is an actionable lockout failure. Every error created by a
// state transition carries the hierarchy, the policy that was authoritative at
// the failure, the reset generation/epoch/revision, the TPM response when one
// exists, and the stage that failed. The original cause remains available via
// errors.Is/errors.As through Unwrap.
type LockoutError struct {
	Stage      LockoutStage           `json:"stage"`
	Hierarchy  TPMHandle              `json:"hierarchy"`
	Policy     DictionaryAttackPolicy `json:"policy"`
	Generation uint64                 `json:"generation"`
	Epoch      uint64                 `json:"epoch"`
	Revision   uint64                 `json:"revision"`
	Response   TPMRC                  `json:"response"`
	Cause      error                  `json:"-"`
}

// Error implements error.
func (e *LockoutError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := fmt.Sprintf(
		"tpm2: lockout %s failed (hierarchy %#x, maxTries=%d, recoveryTime=%d, lockoutRecovery=%d, generation=%d, epoch=%d, revision=%d",
		e.Stage,
		uint32(e.Hierarchy),
		e.Policy.MaxTries,
		e.Policy.RecoveryTime,
		e.Policy.LockoutRecovery,
		e.Generation,
		e.Epoch,
		e.Revision,
	)
	if e.Response != TPMRCSuccess {
		msg += fmt.Sprintf(", tpm response %#x", uint32(e.Response))
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg + ")"
}

// Unwrap returns the underlying cause.
func (e *LockoutError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// DictionaryAttackPolicy is the dictionary-attack policy shared by a lockout
// guard and TPM2_DictionaryAttackParameters. The interval fields are in
// seconds, matching the TPM command.
//
// All uint32 combinations are representable by the TPM, including the boundary
// values zero and math.MaxUint32. A MaxTries value of zero is fail-closed: no
// authorization attempt has a failure budget.
type DictionaryAttackPolicy struct {
	MaxTries        uint32 `json:"maxTries"`
	RecoveryTime    uint32 `json:"recoveryTime"`
	LockoutRecovery uint32 `json:"lockoutRecovery"`
}

// Validate checks the policy without imposing implementation-specific limits.
func (p DictionaryAttackPolicy) Validate() error {
	return validateDictionaryAttackPolicy(p, LockoutLimits{})
}

// ValidateLimits checks the policy against limits reported by the underlying
// TPM. A zero limit means that the corresponding field is not constrained.
func (p DictionaryAttackPolicy) ValidateLimits(limits LockoutLimits) error {
	return validateDictionaryAttackPolicy(p, limits)
}

// Command returns the TPM2_DictionaryAttackParameters representation of this
// policy. The caller remains responsible for supplying a session for auth.
func (p DictionaryAttackPolicy) Command(auth AuthHandle) (DictionaryAttackParameters, error) {
	if err := p.Validate(); err != nil {
		return DictionaryAttackParameters{}, err
	}
	if auth.Handle != TPMRHLockout {
		return DictionaryAttackParameters{}, fmt.Errorf(
			"%w: dictionary attack parameters require TPM_RH_LOCKOUT, got %#x",
			ErrInvalidLockoutParameters, auth.Handle)
	}
	return DictionaryAttackParameters{
		AuthHandle:      auth,
		MaxTries:        p.MaxTries,
		RecoveryTime:    p.RecoveryTime,
		LockoutRecovery: p.LockoutRecovery,
	}, nil
}

// DictionaryAttackResetCommand returns a validated
// TPM2_DictionaryAttackLockReset command for the lockout hierarchy.
func DictionaryAttackResetCommand(auth AuthHandle) (DictionaryAttackLockReset, error) {
	if auth.Handle != TPMRHLockout {
		return DictionaryAttackLockReset{}, fmt.Errorf(
			"%w: dictionary attack reset requires TPM_RH_LOCKOUT, got %#x",
			ErrInvalidLockoutParameters, auth.Handle)
	}
	return DictionaryAttackLockReset{LockHandle: auth}, nil
}

// LockoutLimits are optional bounds for a policy. They are typically populated
// from the TPM platform properties TPM_PT_MAX_AUTH_FAIL,
// TPM_PT_LOCKOUT_INTERVAL and TPM_PT_LOCKOUT_RECOVERY. A zero field means that
// the corresponding policy value is not constrained.
type LockoutLimits struct {
	MaxTries        uint32 `json:"maxTries"`
	RecoveryTime    uint32 `json:"recoveryTime"`
	LockoutRecovery uint32 `json:"lockoutRecovery"`
}

func validateDictionaryAttackPolicy(p DictionaryAttackPolicy, limits LockoutLimits) error {
	if limits.MaxTries != 0 && p.MaxTries > limits.MaxTries {
		return fmt.Errorf(
			"%w: maxTries %d exceeds TPM limit %d",
			ErrInvalidLockoutParameters, p.MaxTries, limits.MaxTries)
	}
	if limits.RecoveryTime != 0 && p.RecoveryTime > limits.RecoveryTime {
		return fmt.Errorf(
			"%w: recovery time %d exceeds TPM limit %d",
			ErrInvalidLockoutParameters, p.RecoveryTime, limits.RecoveryTime)
	}
	if limits.LockoutRecovery != 0 && p.LockoutRecovery > limits.LockoutRecovery {
		return fmt.Errorf(
			"%w: lockout recovery %d exceeds TPM limit %d",
			ErrInvalidLockoutParameters, p.LockoutRecovery, limits.LockoutRecovery)
	}
	return nil
}

// LockoutState is the complete, atomic snapshot of dictionary-attack
// protection.
//
// Generation advances only when protection is reset (by
// DictionaryAttackLockReset or owner recovery). Epoch advances whenever a
// policy change, reset, or owner
// recovery invalidates authorization work that started under older state.
// Revision advances on every committed transition and is used for diagnostics.
//
// The state deliberately does not contain authorization values. Lockout and
// owner authorization values are supplied to the guard separately and are
// never persisted.
type LockoutState struct {
	Generation uint64                 `json:"generation"`
	Epoch      uint64                 `json:"epoch"`
	Revision   uint64                 `json:"revision"`
	Policy     DictionaryAttackPolicy `json:"policy"`

	// Pending is non-nil while a durable lockout-hierarchy command is being
	// committed. A pending mutation is a fail-closed state: no new
	// authorization is admitted and no stale response may be published until
	// the transaction is finalized or an owner recovery resolves it.
	Pending *LockoutPending `json:"pending,omitempty"`

	// FailedTries is the number of failed DA-protected authorizations that
	// have been committed.
	FailedTries uint32 `json:"failedTries"`
	// Reserved counts authorizations that have started but whose result has
	// not been committed. Reservations are persisted so a crash cannot make
	// the failure budget disappear.
	Reserved uint32 `json:"reserved"`

	// LockoutAuthFailures and LockoutAuthBlockedUntil implement the
	// lockoutRecovery interval for failed lockout authorization.
	LockoutAuthFailures     uint32    `json:"lockoutAuthFailures"`
	LockoutAuthBlockedUntil time.Time `json:"lockoutAuthBlockedUntil,omitempty"`

	// LastFailure is the time of the most recent committed failure. It is used
	// to apply RecoveryTime.
	LastFailure time.Time `json:"lastFailure,omitempty"`
}

// LockoutPending is the durable intent for a lockout-hierarchy mutation. It is
// written before a TPM command is sent and removed only after the resulting
// state has been committed. A crash at any point leaves this record behind, so
// a restart cannot silently release protection or restore an older policy.
type LockoutPending struct {
	ID         uint64                 `json:"id"`
	Stage      LockoutStage           `json:"stage"`
	Policy     DictionaryAttackPolicy `json:"policy"`
	Generation uint64                 `json:"generation"`
	Epoch      uint64                 `json:"epoch"`
}

// LockedOut reports whether the committed failed-try count has reached the
// policy limit. A zero maxTries therefore locks out immediately. An in-doubt
// transaction also locks out because its outcome is not yet known.
func (s LockoutState) LockedOut() bool {
	return s.Pending != nil || s.FailedTries >= s.Policy.MaxTries
}

// InDoubt reports whether a durable mutation is still in progress or was
// interrupted. In-doubt states are never treated as an authorization grant.
func (s LockoutState) InDoubt() bool {
	return s.Pending != nil
}

// LockoutAuthBlocked reports whether lockout authorization is still inside its
// recovery interval at now.
func (s LockoutState) LockoutAuthBlocked(now time.Time) bool {
	return !s.LockoutAuthBlockedUntil.IsZero() && now.Before(s.LockoutAuthBlockedUntil)
}

// LockoutOptions configures a Lockout guard.
type LockoutOptions struct {
	// LockoutAuth is the authorization value presented to Configure and Reset.
	// The zero value is a valid empty authorization value.
	LockoutAuth []byte

	// OwnerAuth enables owner recovery when non-nil. A non-nil empty slice
	// enables recovery with the TPM's default empty owner authorization. A nil
	// slice disables owner recovery.
	OwnerAuth []byte

	// Limits optionally rejects policies outside the limits supported by the
	// TPM. The zero value imposes no additional limits.
	Limits LockoutLimits

	// Now supplies the clock used for recovery intervals. It defaults to
	// time.Now and is primarily useful for deterministic tests.
	Now func() time.Time
}

// Lockout serializes dictionary-attack state transitions and makes each
// transition durable before it becomes visible to other callers.
//
// A Lockout is safe for concurrent use by multiple goroutines. The store
// backend must provide the same guarantee for its own readers and writers; a
// single Lockout instance should be used for a given store.
type Lockout struct {
	mu sync.Mutex

	store    LockoutStore
	state    LockoutState
	limits   LockoutLimits
	now      func() time.Time
	lockout  []byte
	owner    []byte
	ownerSet bool
}

// NewLockout opens the durable lockout state in store. If no state exists,
// initialPolicy is validated and committed as the first generation. If state
// already exists, it is authoritative and initialPolicy is ignored.
//
// Invalid parameters, corrupt persisted state, and persistence failures all
// fail closed: no default policy is substituted and the guard is not returned.
func NewLockout(store LockoutStore, initialPolicy DictionaryAttackPolicy, opts LockoutOptions) (*Lockout, error) {
	if store == nil {
		return nil, &LockoutError{
			Stage:     LockoutStageConstruct,
			Hierarchy: TPMRHLockout,
			Policy:    initialPolicy,
			Cause:     ErrNilLockoutStore,
		}
	}
	if err := validateLockoutAuthValue(opts.LockoutAuth); err != nil {
		return nil, &LockoutError{
			Stage:     LockoutStageConstruct,
			Hierarchy: TPMRHLockout,
			Policy:    initialPolicy,
			Cause:     err,
		}
	}
	ownerSet := opts.OwnerAuth != nil
	if ownerSet {
		if err := validateLockoutAuthValue(opts.OwnerAuth); err != nil {
			return nil, &LockoutError{
				Stage:     LockoutStageConstruct,
				Hierarchy: TPMRHLockout,
				Policy:    initialPolicy,
				Cause:     err,
			}
		}
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	l := &Lockout{
		store:    store,
		limits:   opts.Limits,
		now:      now,
		lockout:  cloneLockoutBytes(opts.LockoutAuth),
		owner:    cloneLockoutBytes(opts.OwnerAuth),
		ownerSet: ownerSet,
	}

	data, err := store.Load()
	switch {
	case errors.Is(err, ErrNoLockoutState):
		if err := validateDictionaryAttackPolicy(initialPolicy, opts.Limits); err != nil {
			return nil, &LockoutError{
				Stage:     LockoutStageConstruct,
				Hierarchy: TPMRHLockout,
				Policy:    initialPolicy,
				Cause:     err,
			}
		}
		state := LockoutState{
			Generation: 1,
			Epoch:      1,
			Revision:   1,
			Policy:     initialPolicy,
		}
		if err := l.persistState(state); err != nil {
			return nil, &LockoutError{
				Stage:      LockoutStageConstruct,
				Hierarchy:  TPMRHLockout,
				Policy:     initialPolicy,
				Generation: state.Generation,
				Epoch:      state.Epoch,
				Revision:   state.Revision,
				Cause:      err,
			}
		}
		l.state = state
		return l, nil
	case err != nil:
		return nil, &LockoutError{
			Stage:     LockoutStageConstruct,
			Hierarchy: TPMRHLockout,
			Policy:    initialPolicy,
			Cause:     fmt.Errorf("%w: loading state: %w", ErrLockoutPersistence, err),
		}
	}

	state, err := decodeLockoutState(data)
	if err != nil {
		return nil, &LockoutError{
			Stage:     LockoutStageConstruct,
			Hierarchy: TPMRHLockout,
			Policy:    initialPolicy,
			Cause:     err,
		}
	}
	if err := validateLockoutState(state, opts.Limits); err != nil {
		return nil, &LockoutError{
			Stage:      LockoutStageConstruct,
			Hierarchy:  TPMRHLockout,
			Policy:     state.Policy,
			Generation: state.Generation,
			Epoch:      state.Epoch,
			Revision:   state.Revision,
			Cause:      errors.Join(ErrLockoutStateCorrupt, err),
		}
	}
	l.state = state

	// An attempt that was in flight at the last shutdown has an unknown
	// outcome. Charge it as a failure and clear the reservation so a restart
	// cannot silently restore a larger failure budget.
	if state.Reserved != 0 {
		next := state
		next.FailedTries = saturatingAddUint32(next.FailedTries, next.Reserved)
		next.Reserved = 0
		if next.LastFailure.IsZero() {
			next.LastFailure = l.clockNow()
		}
		if err := bumpLockoutRevision(&next); err != nil {
			return nil, err
		}
		if err := l.persistState(next); err != nil {
			return nil, err
		}
		l.state = next
	}
	return l, nil
}

// Snapshot returns a copy of the current committed state. Time-based recovery
// is reflected in the snapshot without weakening the durable state: a restart
// may still observe the older, stricter count until another transition commits.
// Recovery is not applied to an in-doubt transaction, whose outcome is unknown.
func (l *Lockout) Snapshot() LockoutState {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.state.InDoubt() {
		l.recoverLocked(l.clockNow())
	}
	state := l.state
	if state.Pending != nil {
		pending := *state.Pending
		state.Pending = &pending
	}
	return state
}

// State is an alias for Snapshot.
func (l *Lockout) State() LockoutState {
	return l.Snapshot()
}

// Policy returns the currently committed dictionary-attack policy.
func (l *Lockout) Policy() DictionaryAttackPolicy {
	return l.Snapshot().Policy
}

// Generation returns the current reset generation.
func (l *Lockout) Generation() uint64 {
	return l.Snapshot().Generation
}

// Check reports whether a new authorization attempt may start. It does not
// reserve a failure slot; use Begin for that.
func (l *Lockout) Check() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.InDoubt() {
		return l.errorLocked(LockoutStageCheck, lockoutInDoubtCause())
	}
	l.recoverLocked(l.clockNow())
	if l.state.LockedOut() {
		return l.errorLocked(LockoutStageCheck, fmt.Errorf(
			"%w: %d failed tries with maxTries %d",
			ErrLockout, l.state.FailedTries, l.state.Policy.MaxTries))
	}
	if lockoutBudgetUsed(l.state) >= uint64(l.state.Policy.MaxTries) {
		return l.errorLocked(LockoutStageCheck, fmt.Errorf(
			"%w: all %d failure slots are reserved",
			ErrLockout, l.state.Policy.MaxTries))
	}
	return nil
}

// Begin reserves one authorization failure slot and returns a transaction
// handle. The caller must eventually call Succeed or Fail on the returned
// attempt.
//
// Reserving before sending an authorization prevents concurrent requests from
// jointly exceeding maxTries. If the process stops before the result is
// committed, the reservation is charged as a failure on the next open.
func (l *Lockout) Begin() (*LockoutAttempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clockNow()
	if l.state.InDoubt() {
		return nil, l.errorLocked(LockoutStageBegin, lockoutInDoubtCause())
	}
	l.recoverLocked(now)
	if l.state.LockedOut() {
		return nil, l.errorLocked(LockoutStageBegin, fmt.Errorf(
			"%w: %d failed tries with maxTries %d",
			ErrLockout, l.state.FailedTries, l.state.Policy.MaxTries))
	}
	if lockoutBudgetUsed(l.state) >= uint64(l.state.Policy.MaxTries) {
		return nil, l.errorLocked(LockoutStageBegin, fmt.Errorf(
			"%w: all %d failure slots are reserved",
			ErrLockout, l.state.Policy.MaxTries))
	}

	next := l.state
	next.Reserved++
	if err := bumpLockoutRevision(&next); err != nil {
		return nil, l.errorLocked(LockoutStageBegin, err)
	}
	if err := l.commitLocked(next); err != nil {
		return nil, l.errorLocked(LockoutStageBegin, err)
	}
	return &LockoutAttempt{
		lockout:    l,
		generation: next.Generation,
		epoch:      next.Epoch,
	}, nil
}

// Configure atomically replaces the dictionary-attack parameters after
// authenticating with lockoutAuth.
//
// Existing failed-try protection is preserved: the failed count and its
// recovery clock are not reset by a policy change. Outstanding authorization
// attempts are charged as failures before the policy is replaced, so a policy
// change can never release a failure budget that was already reserved. Their
// later responses are rejected as stale. If the new maxTries is lower than the
// preserved failed count, the guard remains locked.
func (l *Lockout) Configure(policy DictionaryAttackPolicy, lockoutAuth []byte) (LockoutState, error) {
	return l.ConfigureWithRunner(policy, lockoutAuth, nil)
}

// ConfigureWithRunner is Configure plus an external mutation that must be
// made durable in the same generation. run is normally a
// TPM2_DictionaryAttackParameters command. When run is non-nil the guard first
// persists an in-doubt intent, executes run, and only then publishes the new
// policy. A crash or persistence failure leaves the in-doubt intent behind, so
// a restart cannot restore the old policy or admit authorizations against an
// unknown generation. OwnerRecover resolves an in-doubt transaction.
func (l *Lockout) ConfigureWithRunner(policy DictionaryAttackPolicy, lockoutAuth []byte, run func() error) (LockoutState, error) {
	if err := validateDictionaryAttackPolicy(policy, l.limits); err != nil {
		return l.stateError(LockoutStageConfigure, &policy, err)
	}
	if err := validateLockoutAuthValue(lockoutAuth); err != nil {
		return l.stateError(LockoutStageConfigure, &policy, err)
	}
	if run == nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.configureLocked(policy, lockoutAuth, l.clockNow())
	}
	return l.runMutation(LockoutStageConfigure, &policy, lockoutAuth, run, func(next *LockoutState) error {
		next.Policy = policy
		// A policy change invalidates outstanding attempts. Charge their
		// reservations instead of silently returning the failure budget.
		next.FailedTries = saturatingAddUint32(next.FailedTries, next.Reserved)
		next.Reserved = 0
		next.LockoutAuthFailures = 0
		next.LockoutAuthBlockedUntil = time.Time{}
		return bumpLockoutEpoch(next)
	})
}

func (l *Lockout) configureLocked(policy DictionaryAttackPolicy, lockoutAuth []byte, now time.Time) (LockoutState, error) {
	if l.state.InDoubt() {
		return l.state, l.errorLocked(LockoutStageConfigure, lockoutInDoubtCause())
	}
	l.recoverLocked(now)
	if err := l.verifyLockoutAuthLocked(lockoutAuth, now); err != nil {
		if errors.Is(err, ErrLockoutAuthRecovery) {
			return l.state, l.errorLocked(LockoutStageConfigure, err)
		}
		return l.state, l.recordLockoutAuthFailureLocked(now, l.errorLocked(LockoutStageConfigure, err))
	}

	next := l.state
	next.Policy = policy
	next.FailedTries = saturatingAddUint32(next.FailedTries, next.Reserved)
	next.Reserved = 0
	next.LockoutAuthFailures = 0
	next.LockoutAuthBlockedUntil = time.Time{}
	if err := bumpLockoutEpoch(&next); err != nil {
		return l.state, l.errorLocked(LockoutStageConfigure, err)
	}
	if err := l.commitLocked(next); err != nil {
		return l.state, l.errorLocked(LockoutStagePersist, err)
	}
	return l.state, nil
}

// Reset atomically clears the failed-try count, reservations, and lockout
// authorization recovery state. A successful reset advances Generation, so an
// authorization response that started before the reset can never be committed
// afterwards.
func (l *Lockout) Reset(lockoutAuth []byte) (LockoutState, error) {
	return l.ResetWithRunner(lockoutAuth, nil)
}

// ResetWithRunner is Reset plus an external mutation that must be made durable
// in the same generation. run is normally a TPM2_DictionaryAttackLockReset
// command. The reset generation is published only after run succeeds and the
// new state is durable. A late response from an older generation is rejected
// before it can write back the old count or policy.
func (l *Lockout) ResetWithRunner(lockoutAuth []byte, run func() error) (LockoutState, error) {
	if err := validateLockoutAuthValue(lockoutAuth); err != nil {
		return l.stateError(LockoutStageReset, nil, err)
	}
	if run == nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.resetLocked(lockoutAuth, l.clockNow())
	}
	return l.runMutation(LockoutStageReset, nil, lockoutAuth, run, func(next *LockoutState) error {
		next.FailedTries = 0
		next.Reserved = 0
		next.LastFailure = time.Time{}
		next.LockoutAuthFailures = 0
		next.LockoutAuthBlockedUntil = time.Time{}
		return bumpLockoutGeneration(next)
	})
}

func (l *Lockout) resetLocked(lockoutAuth []byte, now time.Time) (LockoutState, error) {
	if l.state.InDoubt() {
		return l.state, l.errorLocked(LockoutStageReset, lockoutInDoubtCause())
	}
	l.recoverLocked(now)
	if err := l.verifyLockoutAuthLocked(lockoutAuth, now); err != nil {
		if errors.Is(err, ErrLockoutAuthRecovery) {
			return l.state, l.errorLocked(LockoutStageReset, err)
		}
		return l.state, l.recordLockoutAuthFailureLocked(now, l.errorLocked(LockoutStageReset, err))
	}

	next := l.state
	next.FailedTries = 0
	next.Reserved = 0
	next.LastFailure = time.Time{}
	next.LockoutAuthFailures = 0
	next.LockoutAuthBlockedUntil = time.Time{}
	if err := bumpLockoutGeneration(&next); err != nil {
		return l.state, l.errorLocked(LockoutStageReset, err)
	}
	if err := l.commitLocked(next); err != nil {
		return l.state, l.errorLocked(LockoutStagePersist, err)
	}
	return l.state, nil
}

// OwnerRecover clears dictionary-attack protection using owner
// authorization. It is the emergency recovery path and does not change the
// configured policy. Owner recovery is disabled when LockoutOptions.OwnerAuth
// is nil.
//
// OwnerRecover is also the only path that may resolve an in-doubt mutation.
// That makes an interrupted TPM command fail closed until an authorized owner
// explicitly accepts the recovery.
func (l *Lockout) OwnerRecover(ownerAuth []byte) (LockoutState, error) {
	if !l.ownerSet {
		return l.stateError(LockoutStageOwnerRecover, nil, ErrOwnerRecoveryDisabled)
	}
	if err := validateLockoutAuthValue(ownerAuth); err != nil {
		return l.stateError(LockoutStageOwnerRecover, nil, err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.state.InDoubt() {
		l.recoverLocked(l.clockNow())
	}
	if !lockoutAuthEqual(ownerAuth, l.owner) {
		return l.state, l.errorLocked(LockoutStageOwnerRecover, ErrOwnerAuthFailed)
	}

	next := l.state
	next.Pending = nil
	next.FailedTries = 0
	next.Reserved = 0
	next.LastFailure = time.Time{}
	next.LockoutAuthFailures = 0
	next.LockoutAuthBlockedUntil = time.Time{}
	if err := bumpLockoutGeneration(&next); err != nil {
		return l.state, l.errorLocked(LockoutStageOwnerRecover, err)
	}
	if err := l.commitLocked(next); err != nil {
		return l.state, l.errorLocked(LockoutStagePersist, err)
	}
	return l.state, nil
}

// Resolve is an alias for OwnerRecover, named for in-doubt transactions.
func (l *Lockout) Resolve(ownerAuth []byte) (LockoutState, error) {
	return l.OwnerRecover(ownerAuth)
}

// LockoutAttempt is one reserved authorization attempt. Its result is
// committed only if the reset generation and invalidation epoch still match
// the state that reserved it. A response that arrives after Reset, Configure,
// or OwnerRecover is rejected with ErrStaleLockoutResponse.
type LockoutAttempt struct {
	mu sync.Mutex

	lockout    *Lockout
	generation uint64
	epoch      uint64
	done       bool
}

// Generation returns the reset generation under which the attempt started.
func (a *LockoutAttempt) Generation() uint64 {
	if a == nil {
		return 0
	}
	return a.generation
}

// ResetGeneration is an alias for Generation.
func (a *LockoutAttempt) ResetGeneration() uint64 {
	return a.Generation()
}

// Epoch returns the invalidation epoch under which the attempt started.
func (a *LockoutAttempt) Epoch() uint64 {
	if a == nil {
		return 0
	}
	return a.epoch
}

// Stale reports whether the attempt belongs to a superseded generation, an
// invalidated epoch, or an in-doubt transaction. It does not commit or mutate
// the attempt.
func (a *LockoutAttempt) Stale() bool {
	if a == nil || a.lockout == nil {
		return true
	}
	l := a.lockout
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.InDoubt() {
		return true
	}
	return a.generation != l.state.Generation || a.epoch != l.state.Epoch
}

// Succeed commits a successful authorization result.
func (a *LockoutAttempt) Succeed() error {
	return a.commit(false)
}

// Fail commits a failed authorization result and consumes the reserved
// failure slot.
func (a *LockoutAttempt) Fail() error {
	return a.commit(true)
}

// Commit records the authorization result. success is true for a successful
// authorization and false for a failed one.
func (a *LockoutAttempt) Commit(success bool) error {
	return a.commit(!success)
}

func (a *LockoutAttempt) commit(failed bool) error {
	if a == nil || a.lockout == nil {
		return &LockoutError{
			Stage:     LockoutStageCommit,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		return &LockoutError{
			Stage:     LockoutStageCommit,
			Hierarchy: TPMRHLockout,
			Cause:     ErrLockoutAttemptCommitted,
		}
	}

	l := a.lockout
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clockNow()
	if l.state.InDoubt() {
		return l.errorLocked(LockoutStageCommit, lockoutInDoubtCause())
	}
	l.recoverLocked(now)
	if a.generation != l.state.Generation || a.epoch != l.state.Epoch {
		a.done = true
		return l.errorLocked(LockoutStageCommit, fmt.Errorf(
			"%w: response for generation %d/epoch %d, current state is generation %d/epoch %d",
			ErrStaleLockoutResponse,
			a.generation, a.epoch, l.state.Generation, l.state.Epoch))
	}
	if l.state.Reserved == 0 {
		return l.errorLocked(LockoutStageCommit, ErrInvalidLockoutState)
	}

	next := l.state
	next.Reserved--
	if failed {
		next.FailedTries = saturatingAddUint32(next.FailedTries, 1)
		next.LastFailure = now
	}
	if err := bumpLockoutRevision(&next); err != nil {
		return l.errorLocked(LockoutStageCommit, err)
	}
	if err := l.commitLocked(next); err != nil {
		return l.errorLocked(LockoutStagePersist, err)
	}
	a.done = true
	return nil
}

func (l *Lockout) verifyLockoutAuthLocked(lockoutAuth []byte, now time.Time) error {
	if err := validateLockoutAuthValue(lockoutAuth); err != nil {
		return err
	}
	if l.state.LockoutAuthBlocked(now) {
		return ErrLockoutAuthRecovery
	}
	if !lockoutAuthEqual(lockoutAuth, l.lockout) {
		return ErrLockoutAuthFailed
	}
	return nil
}

func (l *Lockout) recordLockoutAuthFailureLocked(now time.Time, cause error) error {
	next := l.state
	l.applyLockoutAuthFailure(&next, now)
	if err := bumpLockoutRevision(&next); err != nil {
		return l.errorLocked(LockoutStagePersist, err)
	}
	if err := l.commitLocked(next); err != nil {
		return errors.Join(cause, l.errorLocked(LockoutStagePersist, err))
	}
	return cause
}

func (l *Lockout) applyLockoutAuthFailure(next *LockoutState, now time.Time) {
	if next.LockoutAuthFailures < math.MaxUint32 {
		next.LockoutAuthFailures++
	}
	if next.Policy.LockoutRecovery == 0 {
		next.LockoutAuthBlockedUntil = time.Time{}
	} else {
		next.LockoutAuthBlockedUntil = now.Add(
			time.Duration(next.Policy.LockoutRecovery) * time.Second)
	}
}

// runMutation executes an external lockout-hierarchy mutation inside one
// persisted generation. The pending record is the write-ahead intent. It makes
// the interval between the TPM command and the local state publication
// fail-closed across crashes, storage errors, resets, and concurrent late
// authorization responses.
func (l *Lockout) runMutation(stage LockoutStage, policy *DictionaryAttackPolicy, lockoutAuth []byte, run func() error, apply func(*LockoutState) error) (LockoutState, error) {
	l.mu.Lock()
	now := l.clockNow()
	if l.state.InDoubt() {
		state := l.cloneStateLocked()
		err := l.errorLocked(stage, lockoutInDoubtCause())
		l.mu.Unlock()
		return state, err
	}
	l.recoverLocked(now)
	if err := l.verifyLockoutAuthLocked(lockoutAuth, now); err != nil {
		if errors.Is(err, ErrLockoutAuthRecovery) {
			state := l.cloneStateLocked()
			err = l.errorLocked(stage, err)
			l.mu.Unlock()
			return state, err
		}
		err = l.recordLockoutAuthFailureLocked(now, l.errorLocked(stage, err))
		state := l.cloneStateLocked()
		l.mu.Unlock()
		return state, err
	}

	prepared := l.state
	if err := bumpLockoutRevision(&prepared); err != nil {
		state := l.cloneStateLocked()
		err = l.errorLocked(stage, err)
		l.mu.Unlock()
		return state, err
	}
	pendingPolicy := prepared.Policy
	if policy != nil {
		pendingPolicy = *policy
	}
	pendingID := prepared.Revision
	prepared.Pending = &LockoutPending{
		ID:         pendingID,
		Stage:      stage,
		Policy:     pendingPolicy,
		Generation: prepared.Generation,
		Epoch:      prepared.Epoch,
	}
	if err := l.commitLocked(prepared); err != nil {
		state := l.cloneStateLocked()
		err = l.errorLocked(LockoutStagePersist, err)
		l.mu.Unlock()
		return state, err
	}
	l.mu.Unlock()

	runErr := run()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.Pending == nil || l.state.Pending.ID != pendingID {
		state := l.cloneStateLocked()
		return state, l.errorLocked(stage, fmt.Errorf(
			"%w: lockout transaction %d was superseded", ErrStaleLockoutResponse, pendingID))
	}

	if runErr != nil {
		rolled := l.state
		rolled.Pending = nil
		runReport := runErr
		if errors.Is(runErr, TPMRCAuthFail) {
			l.applyLockoutAuthFailure(&rolled, l.clockNow())
			runReport = errors.Join(ErrLockoutAuthFailed, runErr)
		}
		if err := bumpLockoutRevision(&rolled); err != nil {
			state := l.cloneStateLocked()
			return state, l.errorLocked(LockoutStagePersist, errors.Join(runReport, err))
		}
		if err := l.persistState(rolled); err != nil {
			// Keep the durable pending intent. The guard remains fail-closed
			// until an owner explicitly resolves the interrupted mutation.
			state := l.cloneStateLocked()
			return state, l.errorLocked(LockoutStagePersist, errors.Join(runReport, err))
		}
		l.state = rolled
		state := l.cloneStateLocked()
		return state, l.errorLocked(LockoutStageTPM, runReport)
	}

	next := l.state
	next.Pending = nil
	if err := apply(&next); err != nil {
		state := l.cloneStateLocked()
		return state, l.errorLocked(LockoutStagePersist, err)
	}
	if err := l.commitLocked(next); err != nil {
		// The TPM command succeeded but the new local generation could not be
		// published. The pending intent stays on disk, so a restart denies
		// authorization instead of restoring the old policy.
		state := l.cloneStateLocked()
		return state, l.errorLocked(LockoutStagePersist, err)
	}
	return l.cloneStateLocked(), nil
}

func (l *Lockout) cloneStateLocked() LockoutState {
	state := l.state
	if state.Pending != nil {
		pending := *state.Pending
		state.Pending = &pending
	}
	return state
}

func (l *Lockout) errorLocked(stage LockoutStage, cause error) *LockoutError {
	return lockoutErrorForState(stage, l.state, cause)
}

func (l *Lockout) stateError(stage LockoutStage, policy *DictionaryAttackPolicy, cause error) (LockoutState, *LockoutError) {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.cloneStateLocked()
	err := lockoutErrorForState(stage, state, cause)
	if policy != nil {
		err.Policy = *policy
	}
	return state, err
}

func lockoutInDoubtCause() error {
	return errors.Join(ErrLockout, ErrLockoutInDoubt)
}

func lockoutErrorForState(stage LockoutStage, state LockoutState, cause error) *LockoutError {
	err := &LockoutError{
		Stage:      stage,
		Hierarchy:  TPMRHLockout,
		Policy:     state.Policy,
		Generation: state.Generation,
		Epoch:      state.Epoch,
		Revision:   state.Revision,
		Cause:      cause,
	}
	var response TPMRC
	if errors.As(cause, &response) {
		err.Response = response.Canonical()
	} else {
		var fmt1 TPMFmt1Error
		if errors.As(cause, &fmt1) {
			err.Response = fmt1.Canonical()
		}
	}
	return err
}

func (l *Lockout) recoverLocked(now time.Time) {
	if l.state.FailedTries == 0 ||
		l.state.Policy.RecoveryTime == 0 ||
		l.state.LastFailure.IsZero() {
		return
	}
	interval := time.Duration(l.state.Policy.RecoveryTime) * time.Second
	elapsed := now.Sub(l.state.LastFailure)
	if elapsed < interval {
		return
	}
	steps := uint64(elapsed / interval)
	if steps >= uint64(l.state.FailedTries) {
		l.state.FailedTries = 0
		l.state.LastFailure = time.Time{}
		return
	}
	l.state.FailedTries -= uint32(steps)
	l.state.LastFailure = l.state.LastFailure.Add(time.Duration(steps) * interval)
}

func (l *Lockout) commitLocked(next LockoutState) error {
	if err := validateLockoutState(next, l.limits); err != nil {
		return err
	}
	if err := l.persistState(next); err != nil {
		return err
	}
	l.state = next
	return nil
}

func (l *Lockout) persistState(state LockoutState) error {
	data, err := encodeLockoutState(state)
	if err != nil {
		return fmt.Errorf("%w: encoding state: %w", ErrLockoutPersistence, err)
	}
	if err := l.store.Save(data); err != nil {
		return fmt.Errorf("%w: saving state: %w", ErrLockoutPersistence, err)
	}
	return nil
}

func (l *Lockout) clockNow() time.Time {
	return l.now().UTC()
}

func validateLockoutState(state LockoutState, limits LockoutLimits) error {
	if state.Generation == 0 {
		return fmt.Errorf("%w: generation is zero", ErrInvalidLockoutState)
	}
	if state.Epoch == 0 {
		return fmt.Errorf("%w: epoch is zero", ErrInvalidLockoutState)
	}
	if state.Revision == 0 {
		return fmt.Errorf("%w: revision is zero", ErrInvalidLockoutState)
	}
	if err := validateDictionaryAttackPolicy(state.Policy, limits); err != nil {
		return errors.Join(ErrInvalidLockoutState, err)
	}
	if state.Pending != nil {
		if state.Pending.ID == 0 {
			return fmt.Errorf("%w: pending transaction ID is zero", ErrInvalidLockoutState)
		}
		if state.Pending.Stage != LockoutStageConfigure && state.Pending.Stage != LockoutStageReset {
			return fmt.Errorf(
				"%w: unsupported pending stage %q",
				ErrInvalidLockoutState, state.Pending.Stage)
		}
		if err := validateDictionaryAttackPolicy(state.Pending.Policy, limits); err != nil {
			return errors.Join(ErrInvalidLockoutState, err)
		}
		if state.Pending.Generation != state.Generation ||
			state.Pending.Epoch != state.Epoch {
			return fmt.Errorf(
				"%w: pending transaction belongs to generation %d/epoch %d, state is generation %d/epoch %d",
				ErrInvalidLockoutState,
				state.Pending.Generation,
				state.Pending.Epoch,
				state.Generation,
				state.Epoch)
		}
	}
	if uint64(state.Reserved) > uint64(state.Policy.MaxTries) {
		return fmt.Errorf(
			"%w: %d reservations exceed maxTries %d",
			ErrInvalidLockoutState, state.Reserved, state.Policy.MaxTries)
	}
	return nil
}

func validateLockoutAuthValue(value []byte) error {
	if len(value) > MaxLockoutAuthSize {
		return fmt.Errorf(
			"%w: authorization value is %d bytes, maximum is %d",
			ErrInvalidLockoutParameters, len(value), MaxLockoutAuthSize)
	}
	return nil
}

func lockoutAuthEqual(a, b []byte) bool {
	// Hash both values first so the comparison does not reveal their lengths.
	ah := sha256.Sum256(a)
	bh := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

func lockoutBudgetUsed(state LockoutState) uint64 {
	return uint64(state.FailedTries) + uint64(state.Reserved)
}

func saturatingAddUint32(a, b uint32) uint32 {
	sum := uint64(a) + uint64(b)
	if sum > uint64(math.MaxUint32) {
		return math.MaxUint32
	}
	return uint32(sum)
}

func bumpLockoutGeneration(state *LockoutState) error {
	if state.Generation == ^uint64(0) {
		return ErrLockoutCounterExhausted
	}
	state.Generation++
	return bumpLockoutEpoch(state)
}

func bumpLockoutEpoch(state *LockoutState) error {
	if state.Epoch == ^uint64(0) {
		return ErrLockoutCounterExhausted
	}
	state.Epoch++
	return bumpLockoutRevision(state)
}

func bumpLockoutRevision(state *LockoutState) error {
	if state.Revision == ^uint64(0) {
		return ErrLockoutCounterExhausted
	}
	state.Revision++
	return nil
}

func cloneLockoutBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

// LockoutBinding binds an HMAC session to the reset generation and
// invalidation epoch of attempt. A response whose session was created before
// a reset, policy change, owner recovery, or in-doubt mutation is rejected
// with ErrStaleLockoutResponse instead of being accepted as current
// authorization.
func LockoutBinding(attempt *LockoutAttempt) AuthOption {
	return func(options *sessionOptions) {
		options.lockoutAttempt = attempt
	}
}

// BindLockoutAttempt is an alias for LockoutBinding.
func BindLockoutAttempt(attempt *LockoutAttempt) AuthOption {
	return LockoutBinding(attempt)
}

// LockoutGenerationBinding is an alias for LockoutBinding.
func LockoutGenerationBinding(attempt *LockoutAttempt) AuthOption {
	return LockoutBinding(attempt)
}

func (s *pwSession) lockoutAuthValue() []byte {
	if s == nil {
		return nil
	}
	return s.auth
}

func (s *hmacSession) lockoutAuthValue() []byte {
	if s == nil {
		return nil
	}
	return s.auth
}
