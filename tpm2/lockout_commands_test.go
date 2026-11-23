package tpm2

import (
	"errors"
	"math"
	"testing"
)

func TestDictionaryAttackCommandValidation(t *testing.T) {
	valid := DictionaryAttackParameters{
		AuthHandle: AuthHandle{
			Handle: TPMRHLockout,
			Auth:   PasswordAuth(nil),
		},
		MaxTries:        5,
		RecoveryTime:    10,
		LockoutRecovery: 20,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if got := valid.Policy(); got != (DictionaryAttackPolicy{MaxTries: 5, RecoveryTime: 10, LockoutRecovery: 20}) {
		t.Errorf("Policy() = %+v", got)
	}

	atLimit := valid
	if err := atLimit.ValidateLimits(LockoutLimits{
		MaxTries:        5,
		RecoveryTime:    10,
		LockoutRecovery: 20,
	}); err != nil {
		t.Errorf("ValidateLimits(exact) = %v", err)
	}
	overLimit := valid
	overLimit.MaxTries = 6
	if err := overLimit.ValidateLimits(LockoutLimits{MaxTries: 5}); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("ValidateLimits(over) = %v, want ErrInvalidLockoutParameters", err)
	}
	overInterval := valid
	overInterval.RecoveryTime = 11
	if err := overInterval.ValidateLimits(LockoutLimits{RecoveryTime: 10}); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("ValidateLimits(interval) = %v, want ErrInvalidLockoutParameters", err)
	}
	overLockoutRecovery := valid
	overLockoutRecovery.LockoutRecovery = 21
	if err := overLockoutRecovery.ValidateLimits(LockoutLimits{LockoutRecovery: 20}); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("ValidateLimits(lockout recovery) = %v, want ErrInvalidLockoutParameters", err)
	}

	wrongHierarchy := valid
	wrongHierarchy.AuthHandle = AuthHandle{
		Handle: TPMRHOwner,
		Auth:   PasswordAuth(nil),
	}
	if err := wrongHierarchy.Validate(); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("Validate(owner) = %v, want ErrInvalidLockoutParameters", err)
	}

	missingAuth := valid
	missingAuth.AuthHandle = AuthHandle{Handle: TPMRHLockout}
	if err := missingAuth.Validate(); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("Validate(missing auth) = %v, want ErrInvalidLockoutParameters", err)
	}

	oversizedAuth := valid
	oversizedAuth.AuthHandle = AuthHandle{
		Handle: TPMRHLockout,
		Auth:   PasswordAuth(make([]byte, MaxLockoutAuthSize+1)),
	}
	if err := oversizedAuth.Validate(); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("Validate(oversized auth) = %v, want ErrInvalidLockoutParameters", err)
	}

	boundary := valid
	boundary.MaxTries = math.MaxUint32
	boundary.RecoveryTime = math.MaxUint32
	boundary.LockoutRecovery = math.MaxUint32
	if err := boundary.Validate(); err != nil {
		t.Errorf("Validate(max uint32) = %v", err)
	}

	// A bare lockout handle and a named lockout handle use the same empty
	// password authorization as the compatibility form accepted elsewhere.
	bare := valid
	bare.AuthHandle = TPMRHLockout
	if err := bare.Validate(); err != nil {
		t.Errorf("Validate(bare lockout handle) = %v", err)
	}
	named := valid
	named.AuthHandle = NamedHandle{Handle: TPMRHLockout}
	if err := named.Validate(); err != nil {
		t.Errorf("Validate(named lockout handle) = %v", err)
	}
}

func TestDictionaryAttackResetCommandValidation(t *testing.T) {
	valid := DictionaryAttackLockReset{
		LockHandle: AuthHandle{
			Handle: TPMRHLockout,
			Auth:   PasswordAuth(nil),
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	wrongHierarchy := valid
	wrongHierarchy.LockHandle = AuthHandle{
		Handle: TPMRHOwner,
		Auth:   PasswordAuth(nil),
	}
	if err := wrongHierarchy.Validate(); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("Validate(owner) = %v, want ErrInvalidLockoutParameters", err)
	}

	missingAuth := valid
	missingAuth.LockHandle = AuthHandle{Handle: TPMRHLockout}
	if err := missingAuth.Validate(); !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Errorf("Validate(missing auth) = %v, want ErrInvalidLockoutParameters", err)
	}

	// A bare lockout handle uses the default empty password authorization and
	// remains a valid compatibility form.
	bare := valid
	bare.LockHandle = TPMRHLockout
	if err := bare.Validate(); err != nil {
		t.Errorf("Validate(bare lockout handle) = %v", err)
	}
}

func TestDictionaryAttackCommandsFailClosedBeforeTransport(t *testing.T) {
	_, err := (DictionaryAttackParameters{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
	}).Execute(nil)
	if !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Fatalf("DictionaryAttackParameters.Execute(wrong hierarchy) = %v, want ErrInvalidLockoutParameters", err)
	}

	_, err = (DictionaryAttackLockReset{
		LockHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
	}).Execute(nil)
	if !errors.Is(err, ErrInvalidLockoutParameters) {
		t.Fatalf("DictionaryAttackLockReset.Execute(wrong hierarchy) = %v, want ErrInvalidLockoutParameters", err)
	}
}

func TestLockoutErrorCarriesTransactionEvidence(t *testing.T) {
	cause := TPMRCAuthFail
	err := lockoutErrorForState(LockoutStageTPM, LockoutState{
		Generation: 7,
		Epoch:      9,
		Revision:   11,
		Policy:     DictionaryAttackPolicy{MaxTries: 3, RecoveryTime: 4, LockoutRecovery: 5},
	}, cause)
	if !errors.Is(err, TPMRCAuthFail) {
		t.Fatalf("error does not wrap TPM_RC_AUTH_FAIL: %v", err)
	}
	if err.Hierarchy != TPMRHLockout ||
		err.Generation != 7 ||
		err.Epoch != 9 ||
		err.Revision != 11 ||
		err.Policy.MaxTries != 3 ||
		err.Response != TPMRCAuthFail {
		t.Errorf("error evidence = %+v", err)
	}

	fmt1 := TPMFmt1Error{canonical: TPMRCAuthFail, subject: handleRelated, index: 0}
	if got := fmt1.Canonical(); got != TPMRCAuthFail {
		t.Errorf("TPMFmt1Error.Canonical() = %#x, want %#x", uint32(got), uint32(TPMRCAuthFail))
	}
	selected := TPMRCAuthFail | rcS | (1 << 8)
	if got := selected.Canonical(); got != TPMRCAuthFail {
		t.Errorf("TPMRC.Canonical(selected) = %#x, want %#x", uint32(got), uint32(TPMRCAuthFail))
	}
	selectedErr := lockoutErrorForState(LockoutStageTPM, LockoutState{}, selected)
	if selectedErr.Response != TPMRCAuthFail {
		t.Errorf("selected response = %#x, want canonical %#x",
			uint32(selectedErr.Response), uint32(TPMRCAuthFail))
	}
}
