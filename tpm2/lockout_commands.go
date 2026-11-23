package tpm2

import "fmt"

// Policy returns the dictionary-attack policy carried by cmd.
func (cmd DictionaryAttackParameters) Policy() DictionaryAttackPolicy {
	return DictionaryAttackPolicy{
		MaxTries:        cmd.MaxTries,
		RecoveryTime:    cmd.RecoveryTime,
		LockoutRecovery: cmd.LockoutRecovery,
	}
}

// Validate checks the parts of TPM2_DictionaryAttackParameters that are
// independent of a particular TPM's limits: the command must target
// TPM_RH_LOCKOUT, must carry an authorization session when the handle is an
// AuthHandle, and its authorization value must fit in a TPM2B_AUTH.
//
// All uint32 policy values are accepted here because the TPM command itself
// accepts them. ValidateLimits additionally rejects values outside the limits
// reported by a specific TPM.
func (cmd DictionaryAttackParameters) Validate() error {
	return cmd.ValidateLimits(LockoutLimits{})
}

// ValidateLimits validates cmd and checks its values against limits reported
// by the TPM. A zero limit means that the corresponding policy field is not
// constrained.
func (cmd DictionaryAttackParameters) ValidateLimits(limits LockoutLimits) error {
	if cmd.AuthHandle == nil {
		return &LockoutError{
			Stage:     LockoutStageConfigure,
			Hierarchy: TPMRHLockout,
			Policy:    cmd.Policy(),
			Cause:     fmt.Errorf("%w: missing auth handle", ErrInvalidLockoutParameters),
		}
	}
	if cmd.AuthHandle.HandleValue() != TPMRHLockout.HandleValue() {
		return &LockoutError{
			Stage:     LockoutStageConfigure,
			Hierarchy: TPMRHLockout,
			Policy:    cmd.Policy(),
			Cause: fmt.Errorf(
				"%w: dictionary attack parameters require TPM_RH_LOCKOUT, got %#x",
				ErrInvalidLockoutParameters, cmd.AuthHandle.HandleValue()),
		}
	}
	if auth, ok := cmd.AuthHandle.(AuthHandle); ok {
		if auth.Auth == nil {
			return &LockoutError{
				Stage:     LockoutStageConfigure,
				Hierarchy: TPMRHLockout,
				Policy:    cmd.Policy(),
				Cause:     fmt.Errorf("%w: missing lockout authorization", ErrInvalidLockoutParameters),
			}
		}
		if value, ok := auth.Auth.(interface{ lockoutAuthValue() []byte }); ok {
			if err := validateLockoutAuthValue(value.lockoutAuthValue()); err != nil {
				return &LockoutError{
					Stage:     LockoutStageConfigure,
					Hierarchy: TPMRHLockout,
					Policy:    cmd.Policy(),
					Cause:     err,
				}
			}
		}
	}
	if err := validateDictionaryAttackPolicy(cmd.Policy(), limits); err != nil {
		return &LockoutError{
			Stage:     LockoutStageConfigure,
			Hierarchy: TPMRHLockout,
			Policy:    cmd.Policy(),
			Cause:     err,
		}
	}
	return nil
}

// Validate checks that TPM2_DictionaryAttackLockReset targets TPM_RH_LOCKOUT
// and carries an authorization session when the handle is an AuthHandle.
func (cmd DictionaryAttackLockReset) Validate() error {
	if cmd.LockHandle == nil {
		return &LockoutError{
			Stage:     LockoutStageReset,
			Hierarchy: TPMRHLockout,
			Cause:     fmt.Errorf("%w: missing lock handle", ErrInvalidLockoutParameters),
		}
	}
	if cmd.LockHandle.HandleValue() != TPMRHLockout.HandleValue() {
		return &LockoutError{
			Stage:     LockoutStageReset,
			Hierarchy: TPMRHLockout,
			Cause: fmt.Errorf(
				"%w: dictionary attack reset requires TPM_RH_LOCKOUT, got %#x",
				ErrInvalidLockoutParameters, cmd.LockHandle.HandleValue()),
		}
	}
	if auth, ok := cmd.LockHandle.(AuthHandle); ok {
		if auth.Auth == nil {
			return &LockoutError{
				Stage:     LockoutStageReset,
				Hierarchy: TPMRHLockout,
				Cause:     fmt.Errorf("%w: missing lockout authorization", ErrInvalidLockoutParameters),
			}
		}
		if value, ok := auth.Auth.(interface{ lockoutAuthValue() []byte }); ok {
			if err := validateLockoutAuthValue(value.lockoutAuthValue()); err != nil {
				return &LockoutError{
					Stage:     LockoutStageReset,
					Hierarchy: TPMRHLockout,
					Cause:     err,
				}
			}
		}
	}
	return nil
}

// ParametersCommand is an alias for Command.
func (p DictionaryAttackPolicy) ParametersCommand(auth AuthHandle) (DictionaryAttackParameters, error) {
	return p.Command(auth)
}

// ResetCommand is an alias for DictionaryAttackResetCommand.
func (p DictionaryAttackPolicy) ResetCommand(auth AuthHandle) (DictionaryAttackLockReset, error) {
	return DictionaryAttackResetCommand(auth)
}
