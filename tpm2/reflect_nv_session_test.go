package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// nvFakeTPM is a transport.TPM that synthesizes authenticated TPM responses
// without a real TPM. It implements just enough of the wire protocol to drive
// execute() through an NV write failure followed by a successful retry, which
// is the scenario where a reusable session used to get desynchronized.
//
// Every response HMAC is computed from the nonceCaller carried by the command
// it answers, so the response is authentic relative to the session's current
// key material (an unbound, unsalted HMAC session whose HMAC key is simply the
// trimmed authorization value).
type nvFakeTPM struct {
	t *testing.T
	// session is the local session whose state is used to build responses.
	session *hmacSession
	// responseNonce is the nonceTPM placed in the next response. Each
	// response advances it, as a real TPM would.
	responseNonce []byte
	// failNext, when true, makes the next response an NV error response.
	failNext bool
	// failureRC is the response code used while failNext is set.
	failureRC TPMRC
	// commands records every command the fake TPM received.
	commands [][]byte
}

func (f *nvFakeTPM) Send(cmd []byte) ([]byte, error) {
	f.commands = append(f.commands, append([]byte{}, cmd...))

	// NVWrite command layout:
	//   header(10) | authHandle(4) | nvIndex(4) | authSize(4) |
	//   authArea... | parameters
	const headerSize = 10
	// NVWrite carries two handle-area values (the authorization handle and
	// the NV index), only the first of which has an authorization session.
	const handleAreaSize = 4 * 2
	if len(cmd) < headerSize+handleAreaSize+4 {
		f.t.Fatalf("command too short: %d bytes", len(cmd))
	}
	authSizeOffset := headerSize + handleAreaSize
	authSize := binary.BigEndian.Uint32(cmd[authSizeOffset : authSizeOffset+4])
	authBuf := bytes.NewBuffer(
		cmd[authSizeOffset+4 : authSizeOffset+4+int(authSize)])
	authCmd, err := Unmarshal[TPMSAuthCommand](authBuf.Bytes())
	if err != nil {
		f.t.Fatalf("unmarshalling command auth area: %v", err)
	}

	cc := TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	rc := TPMRCSuccess
	if f.failNext {
		rc = f.failureRC
		f.failNext = false
	}

	s := f.session
	rph, err := rpHash(s.hash, rc, cc, nil)
	if err != nil {
		f.t.Fatalf("rpHash: %v", err)
	}
	// The test session is neither bound nor salted, so its HMAC key is just
	// the (trimmed) authorization value, matching hmacSession.Authorize.
	key := hmacKeyFromAuthValue(append([]byte{}, s.auth...))
	mac, err := computeHMAC(s.hash, key, rph, f.responseNonce,
		authCmd.Nonce.Buffer, nil, authCmd.Attributes)
	if err != nil {
		f.t.Fatalf("computeHMAC: %v", err)
	}

	authArea := Marshal(&TPMSAuthResponse{
		Nonce:         TPM2BNonce{Buffer: f.responseNonce},
		Attributes:    authCmd.Attributes,
		Authorization: TPM2BData{Buffer: mac},
	})
	// Error and success NV responses both carry an empty, length-prefixed
	// parameter area (NVWrite has no response parameters), then the auth
	// area.
	body := append(append([]byte{}, 0x00, 0x00, 0x00, 0x00), authArea...)
	hdr := TPMRspHeader{
		Tag:          TPMSTSessions,
		Length:       uint32(headerSize + len(body)),
		ResponseCode: rc,
	}
	return append(Marshal(&hdr), body...), nil
}

var _ transport.TPM = (*nvFakeTPM)(nil)

// newNVTestSession builds an initialized reusable hmacSession without talking
// to a TPM. Its key material is known to nvFakeTPM, which lets the fake answer
// with authentic response HMACs.
func newNVTestSession(auth []byte) *hmacSession {
	s := &hmacSession{
		sessionOptions: defaultOptions(),
		hash:           TPMAlgSHA256,
		nonceSize:      16,
		handle:         TPMHandle(0x02000000),
		nonceCaller:    TPM2BNonce{Buffer: bytes.Repeat([]byte{0x11}, 16)},
		nonceTPM:       TPM2BNonce{Buffer: bytes.Repeat([]byte{0x22}, 16)},
	}
	s.attrs.ContinueSession = true
	s.auth = auth
	s.authSet = true
	return s
}

// TestExecuteRollsSessionForwardOnNVWriteFailure reproduces the reported
// failure at the session layer: when an NV write fails, the TPM's error
// response still advances the reusable authorization session's nonceTPM. The
// library must validate that response and roll the local session forward, so
// the retried write (and the following read) are authorized with the current
// nonce instead of the stale, pre-failure one.
func TestExecuteRollsSessionForwardOnNVWriteFailure(t *testing.T) {
	auth := []byte("owner-auth")
	s := newNVTestSession(auth)
	failureNonce := bytes.Repeat([]byte{0x33}, 16)
	successNonce := bytes.Repeat([]byte{0x44}, 16)
	fake := &nvFakeTPM{
		t:             t,
		session:       s,
		responseNonce: failureNonce,
		failNext:      true,
		failureRC:     TPMRCNVRange,
	}

	index := TPMHandle(0x01800020)
	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   s,
		},
		NVIndex: NamedHandle{
			Handle: index,
			Name:   HandleName(index),
		},
		Data: TPM2BMaxNVBuffer{Buffer: []byte{1, 2, 3, 4}},
	}

	nonceBefore := append([]byte{}, s.nonceTPM.Buffer...)

	// The first write fails. The error must surface verbatim, but the
	// authenticated error response must have advanced the session.
	if _, err := write.Execute(fake); !errors.Is(err, TPMRCNVRange) {
		t.Fatalf("first NV write: want TPM_RC_NV_RANGE, got %v", err)
	}
	if bytes.Equal(s.nonceTPM.Buffer, nonceBefore) {
		t.Fatal("the failed NV write did not advance the session's nonceTPM; " +
			"the retry would authorize with a stale nonce")
	}
	if !bytes.Equal(s.nonceTPM.Buffer, failureNonce) {
		t.Fatalf("nonceTPM = %x, want the error response nonce %x", s.nonceTPM.Buffer, failureNonce)
	}

	// The retry succeeds. The fake answers with a fresh nonce, and the local
	// session tracks it.
	fake.responseNonce = successNonce
	if _, err := write.Execute(fake); err != nil {
		t.Fatalf("retried NV write: %v", err)
	}
	if !bytes.Equal(s.nonceTPM.Buffer, successNonce) {
		t.Fatalf("nonceTPM = %x, want the success response nonce %x", s.nonceTPM.Buffer, successNonce)
	}
	if len(fake.commands) != 2 {
		t.Fatalf("fake TPM saw %d commands, want 2 (failed write and retry)", len(fake.commands))
	}
	// The two commands must be distinct: execute refreshes nonceCaller on
	// every call, so the retry can never be a byte-for-byte replay of the
	// failed command.
	if bytes.Equal(fake.commands[0], fake.commands[1]) {
		t.Error("the retried NV write replayed the failed command bytes verbatim")
	}
}

// TestExecutePreservesNVErrorCodeWithoutSessions makes sure commands without
// any authorization session still surface the TPM's exact NV error code. The
// new error path must not widen or alter existing codes, and must not panic on
// a missing authorization area.
func TestExecutePreservesNVErrorCodeWithoutSessions(t *testing.T) {
	hdr := TPMRspHeader{
		Tag:          TPMSTNoSessions,
		Length:       10,
		ResponseCode: TPMRCNVUnavailable,
	}
	fake := &staticResponseTPM{response: Marshal(&hdr)}
	_, err := NVReadPublic{NVIndex: TPMHandle(0x01800020)}.Execute(fake)
	if !errors.Is(err, TPMRCNVUnavailable) {
		t.Fatalf("want TPM_RC_NV_UNAVAILABLE preserved, got %v", err)
	}
}

// staticResponseTPM returns a fixed response regardless of the command.
type staticResponseTPM struct {
	response []byte
}

func (s *staticResponseTPM) Send(_ []byte) ([]byte, error) {
	return s.response, nil
}

var _ transport.TPM = (*staticResponseTPM)(nil)
