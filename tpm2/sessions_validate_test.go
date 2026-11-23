package tpm2

import (
	"bytes"
	"errors"
	"testing"
)

func newValidateTestHMACSession() *hmacSession {
	return &hmacSession{
		sessionOptions: defaultOptions(),
		hash:           TPMAlgSHA256,
		nonceSize:      16,
		handle:         TPMHandle(0x03000001),
		nonceCaller:    TPM2BNonce{Buffer: []byte("nonce-caller")},
		nonceTPM:       TPM2BNonce{Buffer: []byte("nonce-tpm-old")},
	}
}

func validResponseAuth(t *testing.T, sess *hmacSession, parms []byte, nonce []byte, attrs TPMASession) *TPMSAuthResponse {
	t.Helper()
	rph, err := rpHash(sess.hash, TPMRCSuccess, TPMCCEncryptDecrypt2, parms)
	if err != nil {
		t.Fatalf("rpHash: %v", err)
	}
	mac, err := computeHMAC(sess.hash, nil, rph, nonce, sess.nonceCaller.Buffer, nil, attrs)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	return &TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: nonce},
		Attributes:    attrs,
		Authorization: TPM2BData{Buffer: mac},
	}
}

func TestHMACSessionValidateDoesNotCommitUnauthenticatedResponse(t *testing.T) {
	sess := newValidateTestHMACSession()
	oldNonce := append([]byte(nil), sess.nonceTPM.Buffer...)
	oldHandle := sess.handle
	attrs := TPMASession{ContinueSession: true}
	auth := &TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: []byte("nonce-tpm-forged")},
		Attributes:    attrs,
		Authorization: TPM2BData{Buffer: []byte("not-a-valid-hmac")},
	}

	err := sess.Validate(TPMRCSuccess, TPMCCEncryptDecrypt2, []byte{0x01, 0x02}, nil, 0, auth)
	if err == nil {
		t.Fatal("Validate accepted an invalid response HMAC")
	}
	if !errors.Is(err, ErrSessionAuthorization) {
		t.Errorf("Validate error = %v, want ErrSessionAuthorization", err)
	}
	if !bytes.Equal(sess.nonceTPM.Buffer, oldNonce) {
		t.Errorf("nonceTPM = %x after failed validation, want %x", sess.nonceTPM.Buffer, oldNonce)
	}
	if sess.handle != oldHandle {
		t.Errorf("handle = %#x after failed validation, want %#x", sess.handle, oldHandle)
	}
}

func TestHMACSessionValidateCommitsAuthenticatedResponse(t *testing.T) {
	sess := newValidateTestHMACSession()
	parms := []byte{0x01, 0x02}
	newNonce := []byte("nonce-tpm-new")
	attrs := TPMASession{ContinueSession: true}
	auth := validResponseAuth(t, sess, parms, newNonce, attrs)

	if err := sess.Validate(TPMRCSuccess, TPMCCEncryptDecrypt2, parms, nil, 0, auth); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !bytes.Equal(sess.nonceTPM.Buffer, newNonce) {
		t.Errorf("nonceTPM = %x, want %x", sess.nonceTPM.Buffer, newNonce)
	}
	if sess.handle != TPMHandle(0x03000001) {
		t.Errorf("handle = %#x, want %#x", sess.handle, TPMHandle(0x03000001))
	}

	// A response without ContinueSession still commits the authenticated
	// nonceTPM, then records that the TPM closed the session.
	attrs = TPMASession{}
	auth = validResponseAuth(t, sess, parms, []byte("nonce-tpm-last"), attrs)
	if err := sess.Validate(TPMRCSuccess, TPMCCEncryptDecrypt2, parms, nil, 0, auth); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !bytes.Equal(sess.nonceTPM.Buffer, []byte("nonce-tpm-last")) {
		t.Errorf("nonceTPM = %x, want %x", sess.nonceTPM.Buffer, "nonce-tpm-last")
	}
	if sess.handle != TPMRHNull {
		t.Errorf("handle = %#x after non-continuing response, want TPM_RH_NULL", sess.handle)
	}
}

func TestPolicySessionValidateDoesNotCommitUnauthenticatedResponse(t *testing.T) {
	sess := &policySession{
		sessionOptions: defaultOptions(),
		hash:           TPMAlgSHA256,
		handle:         TPMHandle(0x03000002),
		nonceCaller:    TPM2BNonce{Buffer: []byte("policy-caller")},
		nonceTPM:       TPM2BNonce{Buffer: []byte("policy-tpm-old")},
	}
	oldNonce := append([]byte(nil), sess.nonceTPM.Buffer...)
	auth := &TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: []byte("policy-tpm-forged")},
		Attributes:    TPMASession{ContinueSession: true},
		Authorization: TPM2BData{Buffer: []byte("not-a-valid-hmac")},
	}
	err := sess.Validate(TPMRCSuccess, TPMCCEncryptDecrypt2, []byte{0x01}, nil, 0, auth)
	if err == nil {
		t.Fatal("Validate accepted an invalid policy response HMAC")
	}
	if !errors.Is(err, ErrSessionAuthorization) {
		t.Errorf("Validate error = %v, want ErrSessionAuthorization", err)
	}
	if !bytes.Equal(sess.nonceTPM.Buffer, oldNonce) {
		t.Errorf("nonceTPM = %x after failed validation, want %x", sess.nonceTPM.Buffer, oldNonce)
	}
	if sess.handle != TPMHandle(0x03000002) {
		t.Errorf("handle = %#x after failed validation, want %#x", sess.handle, TPMHandle(0x03000002))
	}
}
