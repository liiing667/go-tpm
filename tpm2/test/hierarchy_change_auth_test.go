package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestHierarchyChangeAuth(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	authKey := []byte("authkey")
	newAuthKey := []byte("newAuthKey")

	t.Run("HierarchyChangeAuthOwner", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: TPMRHOwner,
			NewAuth: TPM2BAuth{
				Buffer: authKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuth: %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerUnauth", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: TPMRHOwner,
			NewAuth: TPM2BAuth{
				Buffer: newAuthKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if !errors.Is(err, TPMRCBadAuth) {
			t.Errorf("failed HierarchyChangeAuthWithoutAuth: want TPM_RC_BAD_AUTH, got %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerAuth", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   PasswordAuth(authKey),
			},
			NewAuth: TPM2BAuth{
				Buffer: newAuthKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithAuth: %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerHMAC", func(t *testing.T) {
		// The TPM computes the response HMAC with the new auth value.
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   HMAC(TPMAlgSHA256, 16, Auth(newAuthKey)),
			},
			NewAuth: TPM2BAuth{
				Buffer: authKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithHMAC: %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerHMACEmpty", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   HMAC(TPMAlgSHA256, 16, Auth(authKey)),
			},
			NewAuth: TPM2BAuth{
				Buffer: nil,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithHMAC to the empty auth value: %v", err)
		}
	})
}

// TestHierarchyChangeAuthFailureAtomicity verifies that a failed
// HierarchyChangeAuth commits nothing: the old auth value keeps
// authorizing, the attempted new one does not, and the change can be
// retried. Once a change succeeds, the old auth value must not authorize
// anymore.
func TestHierarchyChangeAuthFailureAtomicity(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	oldAuth := []byte("oldAuth")
	newAuth := []byte("newAuth")
	wrongAuth := []byte("wrongAuth")

	// currentAuth tracks the owner hierarchy's auth value so the test
	// can always restore the empty auth value.
	currentAuth := []byte(nil)
	setOwnerAuth := func(from, to []byte) {
		t.Helper()
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(from)},
			NewAuth:    TPM2BAuth{Buffer: to},
		}
		if _, err := hca.Execute(thetpm); err != nil {
			t.Fatalf("setting owner auth: %v", err)
		}
		currentAuth = to
	}
	defer func() {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(currentAuth)},
			NewAuth:    TPM2BAuth{Buffer: nil},
		}
		if _, err := hca.Execute(thetpm); err != nil {
			t.Errorf("restoring empty owner auth: %v", err)
		}
	}()
	setOwnerAuth(nil, oldAuth)

	// A change attempted with the wrong auth value must fail and commit
	// nothing.
	hca := HierarchyChangeAuth{
		AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(wrongAuth)},
		NewAuth:    TPM2BAuth{Buffer: newAuth},
	}
	if _, err := hca.Execute(thetpm); !errors.Is(err, TPMRCBadAuth) {
		t.Fatalf("HierarchyChangeAuth with wrong auth: want TPM_RC_BAD_AUTH, got %v", err)
	}
	// The attempted new auth value must not authorize.
	hca.AuthHandle = AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(newAuth)}
	if _, err := hca.Execute(thetpm); !errors.Is(err, TPMRCBadAuth) {
		t.Fatalf("HierarchyChangeAuth with uncommitted new auth: want TPM_RC_BAD_AUTH, got %v", err)
	}
	// The old auth value still authorizes: retry the change.
	setOwnerAuth(oldAuth, newAuth)
	// After the successful change, the old auth value must not
	// authorize anymore.
	hca.AuthHandle = AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(oldAuth)}
	hca.NewAuth = TPM2BAuth{Buffer: oldAuth}
	if _, err := hca.Execute(thetpm); !errors.Is(err, TPMRCBadAuth) {
		t.Fatalf("HierarchyChangeAuth with replaced auth: want TPM_RC_BAD_AUTH, got %v", err)
	}
}

// TestHierarchyChangeAuthReusableSession verifies that a reusable HMAC
// session survives a failed command without state corruption, and that a
// successful HierarchyChangeAuth commits the new auth value to the
// session exactly once: the same session then authorizes with the new
// value, and only with the new value.
func TestHierarchyChangeAuthReusableSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	oldAuth := []byte("oldAuth")
	newAuth := []byte("newAuth")

	currentAuth := []byte(nil)
	defer func() {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(currentAuth)},
			NewAuth:    TPM2BAuth{Buffer: nil},
		}
		if _, err := hca.Execute(thetpm); err != nil {
			t.Errorf("restoring empty owner auth: %v", err)
		}
	}()

	// Set the owner auth to oldAuth.
	hca := HierarchyChangeAuth{
		AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(nil)},
		NewAuth:    TPM2BAuth{Buffer: oldAuth},
	}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Fatalf("setting owner auth: %v", err)
	}
	currentAuth = oldAuth

	sess, closeSess, err := HMACSession(thetpm, TPMAlgSHA256, 16, Auth(oldAuth))
	if err != nil {
		t.Fatalf("creating HMAC session: %v", err)
	}
	defer closeSess()

	// A command that fails after its authorization check (TPM2_Clear
	// requires TPM_RH_LOCKOUT or TPM_RH_PLATFORM) must not corrupt the
	// reusable session's state.
	clr := Clear{AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: sess}}
	if _, err := clr.Execute(thetpm); !errors.Is(err, TPMRCHierarchy) {
		t.Fatalf("Clear with the owner handle: want TPM_RC_HIERARCHY, got %v", err)
	}

	// The session still carries the old auth value: use it to change
	// the owner auth.
	hca.AuthHandle = AuthHandle{Handle: TPMRHOwner, Auth: sess}
	hca.NewAuth = TPM2BAuth{Buffer: newAuth}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Fatalf("HierarchyChangeAuth with reusable session: %v", err)
	}
	currentAuth = newAuth

	// The session committed the new auth value exactly once: it
	// authorizes the next command with the new value.
	hca.NewAuth = TPM2BAuth{Buffer: oldAuth}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Fatalf("HierarchyChangeAuth with the committed session auth: %v", err)
	}
	currentAuth = oldAuth
}

// TestHierarchyChangeAuthTargetIsolation verifies that changing the owner
// hierarchy's auth value does not affect the endorsement and lockout
// hierarchies or objects made persistent before the change, and that the
// old auth value stops authorizing only the owner hierarchy.
func TestHierarchyChangeAuthTargetIsolation(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	ownerAuth := []byte("ownerAuth")
	endorsementAuth := []byte("endorsementAuth")
	lockoutAuth := []byte("lockoutAuth")

	// Persist an object under the owner hierarchy before the change.
	srkCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}
	srk, err := srkCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("creating primary: %v", err)
	}
	if _, err := (EvictControl{
		Auth: TPMRHOwner,
		ObjectHandle: &NamedHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
		},
		PersistentHandle: 0x81000000,
	}).Execute(thetpm); err != nil {
		t.Fatalf("persisting primary: %v", err)
	}
	// Clean up the persistent object (after the owner auth has been
	// restored to empty by the deferred reset below).
	defer func() {
		rp, err := ReadPublic{ObjectHandle: TPMHandle(0x81000000)}.Execute(thetpm)
		if err != nil {
			t.Errorf("reading persistent object for cleanup: %v", err)
			return
		}
		if _, err := (EvictControl{
			Auth: TPMRHOwner,
			ObjectHandle: &NamedHandle{
				Handle: TPMHandle(0x81000000),
				Name:   rp.Name,
			},
			PersistentHandle: 0x81000000,
		}).Execute(thetpm); err != nil {
			t.Errorf("cleaning up persistent object: %v", err)
		}
	}()

	currentOwnerAuth := []byte(nil)
	defer func() {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(currentOwnerAuth)},
			NewAuth:    TPM2BAuth{Buffer: nil},
		}
		if _, err := hca.Execute(thetpm); err != nil {
			t.Errorf("restoring empty owner auth: %v", err)
		}
	}()

	// Change the owner hierarchy's auth value.
	hca := HierarchyChangeAuth{
		AuthHandle: AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(nil)},
		NewAuth:    TPM2BAuth{Buffer: ownerAuth},
	}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Fatalf("changing owner auth: %v", err)
	}
	currentOwnerAuth = ownerAuth

	// The endorsement hierarchy's (empty) auth value is unaffected.
	hea := HierarchyChangeAuth{
		AuthHandle: AuthHandle{Handle: TPMRHEndorsement, Auth: PasswordAuth(nil)},
		NewAuth:    TPM2BAuth{Buffer: endorsementAuth},
	}
	if _, err := hea.Execute(thetpm); err != nil {
		t.Fatalf("changing endorsement auth with empty auth: %v", err)
	}
	hea.AuthHandle = AuthHandle{Handle: TPMRHEndorsement, Auth: PasswordAuth(endorsementAuth)}
	hea.NewAuth = TPM2BAuth{Buffer: nil}
	if _, err := hea.Execute(thetpm); err != nil {
		t.Fatalf("restoring empty endorsement auth: %v", err)
	}

	// The lockout hierarchy's (empty) auth value is unaffected.
	hla := HierarchyChangeAuth{
		AuthHandle: AuthHandle{Handle: TPMRHLockout, Auth: PasswordAuth(nil)},
		NewAuth:    TPM2BAuth{Buffer: lockoutAuth},
	}
	if _, err := hla.Execute(thetpm); err != nil {
		t.Fatalf("changing lockout auth with empty auth: %v", err)
	}
	hla.AuthHandle = AuthHandle{Handle: TPMRHLockout, Auth: PasswordAuth(lockoutAuth)}
	hla.NewAuth = TPM2BAuth{Buffer: nil}
	if _, err := hla.Execute(thetpm); err != nil {
		t.Fatalf("restoring empty lockout auth: %v", err)
	}

	// The persistent object created before the change is unaffected.
	if _, err := (ReadPublic{ObjectHandle: TPMHandle(0x81000000)}).Execute(thetpm); err != nil {
		t.Errorf("reading persistent object after the auth change: %v", err)
	}

	// The old (empty) owner auth value must not authorize anymore.
	hca.AuthHandle = AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(nil)}
	hca.NewAuth = TPM2BAuth{Buffer: nil}
	if _, err := hca.Execute(thetpm); !errors.Is(err, TPMRCBadAuth) {
		t.Fatalf("HierarchyChangeAuth with replaced owner auth: want TPM_RC_BAD_AUTH, got %v", err)
	}

	// The new owner auth value authorizes: restore the empty auth.
	hca.AuthHandle = AuthHandle{Handle: TPMRHOwner, Auth: PasswordAuth(ownerAuth)}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Fatalf("restoring empty owner auth with the new auth: %v", err)
	}
	currentOwnerAuth = nil
}
