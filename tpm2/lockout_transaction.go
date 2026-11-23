package tpm2

import (
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

// LockoutTransaction binds a Lockout guard to the TPM commands that change the
// dictionary-attack policy or reset its counter. Configure and Reset execute
// the corresponding TPM command and publish the local lockout state as one
// generation: a command that fails leaves the previous state authoritative,
// and a command that succeeds without a durable local commit leaves an
// in-doubt state that denies authorization until OwnerRecover resolves it.
//
// A transaction is safe for concurrent use. Begin, Check, Snapshot, Policy,
// and Generation may be used from other goroutines while a TPM command is in
// flight; they observe either the old state or the in-doubt state, never a
// partially-updated policy.
type LockoutTransaction struct {
	mu sync.Mutex

	lockout     *Lockout
	tpm         transport.TPM
	lockoutAuth []byte
}

// NewLockoutTransaction opens durable lockout state and binds it to t.
// initialPolicy is used only when the store does not yet contain state, as in
// NewLockout.
func NewLockoutTransaction(t transport.TPM, store LockoutStore, initialPolicy DictionaryAttackPolicy, opts LockoutOptions) (*LockoutTransaction, error) {
	if t == nil {
		return nil, &LockoutError{
			Stage:     LockoutStageConstruct,
			Hierarchy: TPMRHLockout,
			Policy:    initialPolicy,
			Cause:     ErrNilLockoutTPM,
		}
	}
	lockout, err := NewLockout(store, initialPolicy, opts)
	if err != nil {
		return nil, err
	}
	return &LockoutTransaction{
		lockout:     lockout,
		tpm:         t,
		lockoutAuth: cloneLockoutBytes(opts.LockoutAuth),
	}, nil
}

// Lockout returns the underlying lockout guard.
func (tx *LockoutTransaction) Lockout() *Lockout {
	if tx == nil {
		return nil
	}
	return tx.lockout
}

// Guard is an alias for Lockout.
func (tx *LockoutTransaction) Guard() *Lockout {
	return tx.Lockout()
}

// Snapshot returns a consistent copy of the current protection state.
func (tx *LockoutTransaction) Snapshot() LockoutState {
	if tx == nil || tx.lockout == nil {
		return LockoutState{}
	}
	return tx.lockout.Snapshot()
}

// State is an alias for Snapshot.
func (tx *LockoutTransaction) State() LockoutState {
	return tx.Snapshot()
}

// Policy returns the currently committed dictionary-attack policy.
func (tx *LockoutTransaction) Policy() DictionaryAttackPolicy {
	return tx.Snapshot().Policy
}

// Generation returns the current reset generation.
func (tx *LockoutTransaction) Generation() uint64 {
	return tx.Snapshot().Generation
}

// Check reports whether a new authorization attempt may start.
func (tx *LockoutTransaction) Check() error {
	if tx == nil || tx.lockout == nil {
		return &LockoutError{
			Stage:     LockoutStageCheck,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}
	return tx.lockout.Check()
}

// Begin reserves one authorization failure slot.
func (tx *LockoutTransaction) Begin() (*LockoutAttempt, error) {
	if tx == nil || tx.lockout == nil {
		return nil, &LockoutError{
			Stage:     LockoutStageBegin,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}
	return tx.lockout.Begin()
}

// Configure changes the dictionary-attack parameters and the TPM policy in one
// generation. If the TPM command fails, the local policy is unchanged. If the
// command succeeds but the local state cannot be made durable, the guard keeps
// an in-doubt record and denies authorization until OwnerRecover is used.
func (tx *LockoutTransaction) Configure(policy DictionaryAttackPolicy) (LockoutState, error) {
	if tx == nil || tx.lockout == nil {
		return LockoutState{}, &LockoutError{
			Stage:     LockoutStageConfigure,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	auth := cloneLockoutBytes(tx.lockoutAuth)
	return tx.lockout.ConfigureWithRunner(policy, auth, func() error {
		cmd := DictionaryAttackParameters{
			AuthHandle: AuthHandle{
				Handle: TPMRHLockout,
				Auth:   PasswordAuth(cloneLockoutBytes(auth)),
			},
			MaxTries:        policy.MaxTries,
			RecoveryTime:    policy.RecoveryTime,
			LockoutRecovery: policy.LockoutRecovery,
		}
		_, err := cmd.Execute(tx.tpm)
		return err
	})
}

// Reset resets the TPM dictionary-attack counter and the local reset
// generation in one generation. A late authorization response from an earlier
// generation is rejected by LockoutAttempt before it can restore the old count.
func (tx *LockoutTransaction) Reset() (LockoutState, error) {
	if tx == nil || tx.lockout == nil {
		return LockoutState{}, &LockoutError{
			Stage:     LockoutStageReset,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	auth := cloneLockoutBytes(tx.lockoutAuth)
	return tx.lockout.ResetWithRunner(auth, func() error {
		cmd := DictionaryAttackLockReset{
			LockHandle: AuthHandle{
				Handle: TPMRHLockout,
				Auth:   PasswordAuth(cloneLockoutBytes(auth)),
			},
		}
		_, err := cmd.Execute(tx.tpm)
		return err
	})
}

// OwnerRecover clears protection and resolves an in-doubt transaction using
// owner authorization. It does not change the configured policy.
func (tx *LockoutTransaction) OwnerRecover(ownerAuth []byte) (LockoutState, error) {
	if tx == nil || tx.lockout == nil {
		return LockoutState{}, &LockoutError{
			Stage:     LockoutStageOwnerRecover,
			Hierarchy: TPMRHLockout,
			Cause:     ErrInvalidLockoutState,
		}
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.lockout.OwnerRecover(ownerAuth)
}

// Resolve is an alias for OwnerRecover, named for in-doubt transactions.
func (tx *LockoutTransaction) Resolve(ownerAuth []byte) (LockoutState, error) {
	return tx.OwnerRecover(ownerAuth)
}

// ErrLockoutTransactionInDoubt is an alias for ErrLockoutInDoubt.
var ErrLockoutTransactionInDoubt = ErrLockoutInDoubt
