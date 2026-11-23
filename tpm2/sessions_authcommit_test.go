package tpm2

import (
	"bytes"
	"sync"
	"testing"
)

// authRsp builds the response auth area that a TPM would produce for a
// command whose response HMAC key includes the given auth value.
func authRsp(t *testing.T, cc TPMCC, auth, nonceCaller, nonceTPM []byte) *TPMSAuthResponse {
	t.Helper()
	var hmacKey []byte
	hmacKey = append(hmacKey, hmacKeyFromAuthValue(auth)...)
	rph, err := rpHash(TPMAlgSHA256, TPMRCSuccess, cc, nil)
	if err != nil {
		t.Fatalf("rpHash: %v", err)
	}
	attrs := TPMASession{ContinueSession: true}
	mac, err := computeHMAC(TPMAlgSHA256, hmacKey, rph, nonceTPM, nonceCaller, nil, attrs)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	return &TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: nonceTPM},
		Attributes:    attrs,
		Authorization: TPM2BData{Buffer: mac},
	}
}

// TestHMACSessionStagedAuthCommit verifies that the new auth value of an
// auth-changing command is only staged until the command's response has
// been authenticated, and that the nonce roll and the auth change commit
// together.
func TestHMACSessionStagedAuthCommit(t *testing.T) {
	oldAuth := []byte("old-auth")
	newAuth := []byte("new-auth")
	nonceCaller := bytes.Repeat([]byte{0xAA}, 16)
	oldNonceTPM := bytes.Repeat([]byte{0xBB}, 16)
	newNonceTPM := bytes.Repeat([]byte{0xCC}, 16)

	s := hmacSession{
		sessionOptions: sessionOptions{auth: oldAuth, authSet: true},
		hash:           TPMAlgSHA256,
		handle:         0x02000000,
		nonceCaller:    TPM2BNonce{Buffer: nonceCaller},
		nonceTPM:       TPM2BNonce{Buffer: oldNonceTPM},
	}

	s.updateAuth(newAuth)
	// The staged value must not leak into the session's auth value
	// before the commit.
	if !bytes.Equal(s.auth, oldAuth) {
		t.Errorf("updateAuth replaced the session auth value before the commit")
	}
	// The TPM computes the response HMAC of an auth-changing command
	// with the new auth value.
	rsp := authRsp(t, TPMCCHierarchyChanegAuth, newAuth, nonceCaller, newNonceTPM)
	if err := s.Validate(TPMRCSuccess, TPMCCHierarchyChanegAuth, nil, nil, 0, rsp); err != nil {
		t.Fatalf("Validate with the new auth value: %v", err)
	}
	s.commitAuth()
	if !bytes.Equal(s.auth, newAuth) {
		t.Errorf("commitAuth did not commit the staged auth value")
	}
	if !bytes.Equal(s.nonceTPM.Buffer, newNonceTPM) {
		t.Errorf("Validate did not commit the nonce roll")
	}
}

// TestHMACSessionStagedAuthRollback verifies that a failed validation
// commits nothing: the session keeps the auth value and nonceTPM that
// still match the TPM's state, so the command can be retried.
func TestHMACSessionStagedAuthRollback(t *testing.T) {
	oldAuth := []byte("old-auth")
	newAuth := []byte("new-auth")
	nonceCaller := bytes.Repeat([]byte{0xAA}, 16)
	oldNonceTPM := bytes.Repeat([]byte{0xBB}, 16)
	newNonceTPM := bytes.Repeat([]byte{0xCC}, 16)

	s := hmacSession{
		sessionOptions: sessionOptions{auth: oldAuth, authSet: true},
		hash:           TPMAlgSHA256,
		handle:         0x02000000,
		nonceCaller:    TPM2BNonce{Buffer: nonceCaller},
		nonceTPM:       TPM2BNonce{Buffer: oldNonceTPM},
	}

	s.updateAuth(newAuth)
	// A response authenticated with the old (still current) auth value
	// does not prove the auth change: validation must fail and leave
	// the session state untouched.
	rsp := authRsp(t, TPMCCHierarchyChanegAuth, oldAuth, nonceCaller, newNonceTPM)
	if err := s.Validate(TPMRCSuccess, TPMCCHierarchyChanegAuth, nil, nil, 0, rsp); err == nil {
		t.Errorf("Validate succeeded with the old auth value while a new one was staged")
	}
	s.rollbackAuth()
	if !bytes.Equal(s.auth, oldAuth) {
		t.Errorf("rollbackAuth changed the session auth value")
	}
	if !bytes.Equal(s.nonceTPM.Buffer, oldNonceTPM) {
		t.Errorf("failed validation rolled the session nonceTPM")
	}
	// After the rollback, the session still validates responses
	// authenticated with the old auth value: the command can be
	// retried with the still-current authorization state.
	rsp = authRsp(t, TPMCCGetRandom, oldAuth, nonceCaller, newNonceTPM)
	if err := s.Validate(TPMRCSuccess, TPMCCGetRandom, nil, nil, 0, rsp); err != nil {
		t.Errorf("Validate with the old auth value after rollback: %v", err)
	}
}

// TestPolicySessionStagedAuth verifies the staging rules of policy
// sessions: the auth value is only staged for sessions that were given
// one (with Auth), and only committed on commitAuth.
func TestPolicySessionStagedAuth(t *testing.T) {
	oldAuth := []byte("old-auth")
	newAuth := []byte("new-auth")

	s := policySession{sessionOptions: sessionOptions{auth: oldAuth, authSet: true}}
	s.updateAuth(newAuth)
	if !bytes.Equal(s.auth, oldAuth) {
		t.Errorf("updateAuth replaced the session auth value before the commit")
	}
	s.rollbackAuth()
	s.updateAuth(newAuth)
	s.commitAuth()
	if !bytes.Equal(s.auth, newAuth) {
		t.Errorf("commitAuth did not commit the staged auth value")
	}

	// A password policy session never stages a new auth value.
	pw := policySession{sessionOptions: sessionOptions{auth: oldAuth, authSet: true, password: true}}
	pw.updateAuth(newAuth)
	pw.commitAuth()
	if !bytes.Equal(pw.auth, oldAuth) {
		t.Errorf("password policy session staged an auth value")
	}

	// A policy session without an auth value never stages one.
	noAuth := policySession{sessionOptions: sessionOptions{}}
	noAuth.updateAuth(newAuth)
	noAuth.commitAuth()
	if noAuth.auth != nil {
		t.Errorf("auth-less policy session staged an auth value")
	}
}

// TestSessionConcurrentStateTransitions hammers the mutable state of an
// HMAC session from many goroutines. Run with -race: the session's
// internal locking must make every state transition atomic.
func TestSessionConcurrentStateTransitions(t *testing.T) {
	s := hmacSession{
		sessionOptions: sessionOptions{auth: []byte("auth"), authSet: true},
		hash:           TPMAlgSHA256,
		handle:         0x02000000,
		nonceCaller:    TPM2BNonce{Buffer: make([]byte, 16)},
		nonceTPM:       TPM2BNonce{Buffer: bytes.Repeat([]byte{0xBB}, 16)},
	}
	rsp := &TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: bytes.Repeat([]byte{0xCC}, 16)},
		Attributes:    TPMASession{ContinueSession: true},
		Authorization: TPM2BData{Buffer: []byte("bogus")},
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.updateAuth([]byte("new-auth"))
				// The bogus HMAC makes Validate fail; it must
				// not panic or corrupt the session state.
				_ = s.Validate(TPMRCSuccess, TPMCCHierarchyChanegAuth, nil, nil, 0, rsp)
				s.rollbackAuth()
				s.commitAuth()
				_ = s.NewNonceCaller()
				_ = s.NonceTPM()
				_ = s.Handle()
			}
		}()
	}
	wg.Wait()
}
