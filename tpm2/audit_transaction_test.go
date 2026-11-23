package tpm2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// fakeTPM is an in-process transport.TPM used to drive deterministic command
// transactions without a real TPM. Each queued response is returned verbatim
// for the next Send call; the exact command bytes received are recorded.
type fakeTPM struct {
	responses [][]byte
	sendErrs  []error
	commands  [][]byte
}

func (f *fakeTPM) Send(cmd []byte) ([]byte, error) {
	f.commands = append(f.commands, append([]byte(nil), cmd...))
	i := len(f.commands) - 1
	var err error
	if i < len(f.sendErrs) {
		err = f.sendErrs[i]
	}
	if err != nil {
		return nil, err
	}
	if i >= len(f.responses) {
		return nil, fmt.Errorf("fakeTPM: no queued response for command %d", i+1)
	}
	return f.responses[i], nil
}

// fakeResponse builds a no-session success response carrying the given body.
func fakeResponse(rc TPMRC, body []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, TPMSTNoSessions)
	binary.Write(buf, binary.BigEndian, uint32(10+len(body)))
	binary.Write(buf, binary.BigEndian, rc)
	buf.Write(body)
	return buf.Bytes()
}

// getRandomResponseBody is the TPM2_GetRandom parameter area: a sized digest.
func getRandomResponseBody(data []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
	return buf.Bytes()
}

// fakeSessionResponse builds a successful TPM_ST_SESSIONS response whose
// authorization area contains one empty password-session response, followed by
// the given parameter area.
func fakeSessionResponse(parms []byte) []byte {
	var auth bytes.Buffer
	binary.Write(&auth, binary.BigEndian, TPMRSPW)   // session handle
	binary.Write(&auth, binary.BigEndian, uint16(0)) // nonce size
	auth.WriteByte(0x01)                             // attributes: ContinueSession
	binary.Write(&auth, binary.BigEndian, uint16(0)) // HMAC size

	body := new(bytes.Buffer)
	binary.Write(body, binary.BigEndian, uint32(auth.Len()+len(parms)))
	body.Write(auth.Bytes())
	body.Write(parms)
	return fakeResponseWithTag(TPMSTSessions, TPMRCSuccess, body.Bytes())
}

// fakeResponseWithTag builds a response with an arbitrary command tag.
func fakeResponseWithTag(tag TPMST, rc TPMRC, body []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tag)
	binary.Write(buf, binary.BigEndian, uint32(10+len(body)))
	binary.Write(buf, binary.BigEndian, rc)
	buf.Write(body)
	return buf.Bytes()
}

// expectedGetRandomDigest recomputes the audit digest the library must produce
// for a successful TPM2_GetRandom transaction.
func expectedGetRandomDigest(t *testing.T, previous, cmd GetRandom, rsp *GetRandomResponse) []byte {
	t.Helper()
	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	audit.digest = append([]byte(nil), previous...)
	if err := AuditCommand(audit, cmd, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	return audit.Digest()
}

// TestExecuteWithAuditSuccess proves that a successful command transaction
// extends the audit digest exactly once, using the same command input and
// response the caller receives.
func TestExecuteWithAuditSuccess(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	rspBody := getRandomResponseBody([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	tpm := &fakeTPM{responses: [][]byte{fakeResponse(TPMRCSuccess, rspBody)}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	rsp, err := ExecuteWithAudit(tpm, audit, cmd)
	if err != nil {
		t.Fatalf("ExecuteWithAudit: %v", err)
	}
	if len(tpm.commands) != 1 {
		t.Fatalf("expected 1 Send, got %d", len(tpm.commands))
	}
	if !bytes.Equal(rsp.RandomBytes.Buffer, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("unexpected response bytes: %x", rsp.RandomBytes.Buffer)
	}

	want := expectedGetRandomDigest(t, initial, cmd, rsp)
	if !bytes.Equal(audit.Digest(), want) {
		t.Fatalf("audit digest mismatch:\ngot  %x\nwant %x", audit.Digest(), want)
	}
	// The digest must actually have moved off the all-zero initial value.
	if bytes.Equal(audit.Digest(), initial) {
		t.Fatal("audit digest was not extended by the successful transaction")
	}
}

// TestExecuteWithAuditWarningRetryNotAudited proves that a warning response
// (here TPM_RC_RETRY, the code the TPM returns when the client must retry) is
// never counted into the success audit digest, including when the caller
// retries and the retry succeeds: only the successful transaction is audited,
// exactly once.
func TestExecuteWithAuditWarningRetryNotAudited(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	okBody := getRandomResponseBody([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	tpm := &fakeTPM{responses: [][]byte{
		fakeResponse(TPMRCRetry, getRandomResponseBody([]byte{1, 2, 3, 4})),
		fakeResponse(TPMRCSuccess, okBody),
	}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	// First attempt: the TPM asks the client to retry.
	_, warnErr := ExecuteWithAudit(tpm, audit, cmd)
	if warnErr == nil {
		t.Fatal("first attempt succeeded unexpectedly; want TPM_RC_RETRY error")
	}
	warnRC, ok := warnErr.(TPMRC)
	if !ok || !warnRC.IsWarning() {
		t.Fatalf("first attempt error = %v, want a TPM warning", warnErr)
	}
	if !errors.Is(warnErr, TPMRCRetry) {
		t.Fatalf("first attempt error = %v, want TPM_RC_RETRY", warnErr)
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatalf("audit digest changed after a warning response:\ngot  %x\nwant %x", audit.Digest(), initial)
	}

	// Retry, this time successfully.
	rsp, err := ExecuteWithAudit(tpm, audit, cmd)
	if err != nil {
		t.Fatalf("retried ExecuteWithAudit: %v", err)
	}
	if len(tpm.commands) != 2 {
		t.Fatalf("expected 2 Sends (warning + retry), got %d", len(tpm.commands))
	}
	want := expectedGetRandomDigest(t, initial, cmd, rsp)
	if !bytes.Equal(audit.Digest(), want) {
		t.Fatalf("audit digest after retry mismatch:\ngot  %x\nwant %x", audit.Digest(), want)
	}

	// The warning response must not be reconstructable as the audited
	// transaction: auditing the success twice would give a different digest,
	// proving the summary contains exactly one success and zero warnings.
	double, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	if err := AuditCommand(double, cmd, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	if err := AuditCommand(double, cmd, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	if bytes.Equal(audit.Digest(), double.Digest()) {
		t.Fatal("audit digest looks like the successful response was counted twice")
	}
}

// TestExecuteWithAuditFormatOneErrorNotAudited proves that a genuine TPM
// format-1 error response likewise cannot reach the success-only audit
// summary.
func TestExecuteWithAuditFormatOneErrorNotAudited(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	// TPM_RC_VALUE is a format-1 error (0x100 + 0x004), distinct from the
	// warning space used by TPM_RC_RETRY.
	tpm := &fakeTPM{responses: [][]byte{fakeResponse(TPMRCValue, nil)}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	if _, err := ExecuteWithAudit(tpm, audit, cmd); !errors.Is(err, TPMRCValue) {
		t.Fatalf("ExecuteWithAudit error = %v, want TPM_RC_VALUE", err)
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatalf("audit digest changed after an error response:\ngot  %x\nwant %x", audit.Digest(), initial)
	}
}

// TestExecuteWithAuditTransportAndSessionErrorsNotAudited covers failures
// before any usable response exists: transport errors and short responses.
// The audit digest must remain at its initial value in every case.
func TestExecuteWithAuditTransportAndSessionErrorsNotAudited(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	transportErr := errors.New("device vanished")
	transportTPM := &fakeTPM{sendErrs: []error{transportErr}}
	if _, err := ExecuteWithAudit(transportTPM, audit, cmd); !errors.Is(err, transportErr) {
		t.Fatalf("transport error = %v, want %v", err, transportErr)
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatal("audit digest changed after a transport Send error")
	}

	// A response shorter than the 10-byte header cannot carry a response code.
	shortTPM := &fakeTPM{responses: [][]byte{{0x80, 0x01, 0x00, 0x00}}}
	if _, err := ExecuteWithAudit(shortTPM, audit, cmd); err == nil {
		t.Fatal("short response unexpectedly parsed successfully")
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatal("audit digest changed after a short (unparseable) response")
	}
}

// TestExecuteWithAuditDigestMatchesStructAudit proves the transactional audit
// computes the same digest as the legacy struct-based AuditCommand path, i.e.
// old encoding behavior is preserved for successful commands.
func TestExecuteWithAuditDigestMatchesStructAudit(t *testing.T) {
	cmd := GetRandom{BytesRequested: 8}
	body := getRandomResponseBody([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	tpm := &fakeTPM{responses: [][]byte{fakeResponse(TPMRCSuccess, body)}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	rsp, err := ExecuteWithAudit(tpm, audit, cmd)
	if err != nil {
		t.Fatalf("ExecuteWithAudit: %v", err)
	}

	legacy, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	if err := AuditCommand(legacy, cmd, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	if !bytes.Equal(audit.Digest(), legacy.Digest()) {
		t.Fatalf("transactional and legacy audit digests differ:\ntransactional %x\nlegacy %x",
			audit.Digest(), legacy.Digest())
	}

	// And it matches a direct sha256 construction over the documented
	// cpHash/rpHash preimages for this no-session command.
	h := sha256.New()
	h.Write(make([]byte, sha256.Size))
	cpPreimage := new(bytes.Buffer)
	binary.Write(cpPreimage, binary.BigEndian, TPMCCGetRandom)
	// TPM2_GetRandom has no handles: cpHash preimage is CC || parameters,
	// and its only parameter is the uint16 BytesRequested field.
	binary.Write(cpPreimage, binary.BigEndian, cmd.BytesRequested)
	cp := sha256.Sum256(cpPreimage.Bytes())
	rpPreimage := new(bytes.Buffer)
	binary.Write(rpPreimage, binary.BigEndian, TPMRCSuccess)
	binary.Write(rpPreimage, binary.BigEndian, TPMCCGetRandom)
	rpPreimage.Write(body)
	rp := sha256.Sum256(rpPreimage.Bytes())
	h.Write(cp[:])
	h.Write(rp[:])
	if !bytes.Equal(audit.Digest(), h.Sum(nil)) {
		t.Fatalf("audit digest does not match the cpHash/rpHash construction:\ngot  %x\nwant %x", audit.Digest(), h.Sum(nil))
	}
}

// TestAuditCommandRollsBackOnFailure exercises the atomic-extension helper via
// a digest whose hash cannot be used: a successful audit followed by a failed
// audit attempt must leave the previous digest intact.
func TestAuditCommandRollsBackOnFailure(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	body := getRandomResponseBody([]byte{1, 2, 3, 4})
	tpm := &fakeTPM{responses: [][]byte{fakeResponse(TPMRCSuccess, body)}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	rsp, err := ExecuteWithAudit(tpm, audit, cmd)
	if err != nil {
		t.Fatalf("ExecuteWithAudit: %v", err)
	}
	goodDigest := append([]byte(nil), audit.Digest()...)

	// Corrupt the hash selector so any further hashing fails; the digest must
	// stay equal to goodDigest rather than being partially overwritten.
	audit.hash = TPMIAlgHash(0xFFFF)
	if err := AuditCommand(audit, cmd, rsp); err == nil {
		t.Fatal("AuditCommand with an invalid hash unexpectedly succeeded")
	}
	if !bytes.Equal(audit.Digest(), goodDigest) {
		t.Fatalf("audit digest changed after a failed audit extension:\ngot  %x\nwant %x", audit.Digest(), goodDigest)
	}

	// Same guarantee through the transactional entry point: after the audit
	// hash becomes unusable, a fully successful TPM transaction must be
	// reported as an error and must still leave the digest untouched.
	okTPM := &fakeTPM{responses: [][]byte{fakeResponse(TPMRCSuccess, body)}}
	if _, err := ExecuteWithAudit(okTPM, audit, cmd); err == nil {
		t.Fatal("ExecuteWithAudit unexpectedly succeeded with an unusable audit hash")
	}
	if !bytes.Equal(audit.Digest(), goodDigest) {
		t.Fatalf("audit digest changed after a failed transactional audit:\ngot  %x\nwant %x",
			audit.Digest(), goodDigest)
	}
}

// failingInitSession wraps a real Session but fails during Init, emulating a
// session that cannot be established against the TPM.
type failingInitSession struct {
	Session
	initErr error
}

func (f failingInitSession) Init(_ transport.TPM) error { return f.initErr }

// TestExecuteWithAuditSessionErrorNotAudited proves that when a session cannot
// be initialized, no command is sent, no response exists and the audit digest
// stays at its previous value: a session error cannot be summarized as a
// successful audited command.
func TestExecuteWithAuditSessionErrorNotAudited(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	tpm := &fakeTPM{}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	sessionErr := errors.New("session could not be started")
	badSession := failingInitSession{Session: PasswordAuth(nil), initErr: sessionErr}
	if _, err := ExecuteWithAudit(tpm, audit, cmd, badSession); !errors.Is(err, sessionErr) {
		t.Fatalf("ExecuteWithAudit error = %v, want %v", err, sessionErr)
	}
	if len(tpm.commands) != 0 {
		t.Fatalf("expected no command on the wire after a session Init failure, got %d", len(tpm.commands))
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatalf("audit digest changed after a session error:\ngot  %x\nwant %x", audit.Digest(), initial)
	}
}

// TestExecuteWithAuditWithPasswordSession proves the transactional audit also
// works when the command carries an authorization area: the captured preimages
// exclude the sessions framing, so the digest still matches the struct-based
// audit of the same successful transaction.
func TestExecuteWithAuditWithPasswordSession(t *testing.T) {
	cmd := GetRandom{BytesRequested: 4}
	body := getRandomResponseBody([]byte{9, 8, 7, 6})
	tpm := &fakeTPM{responses: [][]byte{fakeSessionResponse(body)}}

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	// GetRandom takes no auth handles, so the password session is supplied as
	// an extra session and produces a TPM_ST_SESSIONS command.
	rsp, err := ExecuteWithAudit(tpm, audit, cmd, PasswordAuth([]byte("secret")))
	if err != nil {
		t.Fatalf("ExecuteWithAudit: %v", err)
	}
	if len(tpm.commands) != 1 || len(tpm.commands[0]) == 0 || tpm.commands[0][0] != 0x80 || tpm.commands[0][1] != 0x02 {
		t.Fatalf("expected a TPM_ST_SESSIONS (0x8002) command, got % x", tpm.commands[0])
	}

	legacy, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	if err := AuditCommand(legacy, cmd, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	if !bytes.Equal(audit.Digest(), legacy.Digest()) {
		t.Fatalf("session command audit mismatch:\ntransactional %x\nlegacy        %x", audit.Digest(), legacy.Digest())
	}
}
