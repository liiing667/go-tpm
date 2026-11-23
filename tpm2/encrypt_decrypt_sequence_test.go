package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// sequenceTestTPM is a scripted transport.TPM. Each Send consumes one entry
// from responses or errs and records the raw command bytes.
type sequenceTestTPM struct {
	responses [][]byte
	errs      []error
	calls     int
	commands  [][]byte
}

func (t *sequenceTestTPM) Send(input []byte) ([]byte, error) {
	index := t.calls
	t.calls++
	t.commands = append(t.commands, append([]byte(nil), input...))
	if index < len(t.errs) && t.errs[index] != nil {
		return nil, t.errs[index]
	}
	if index < len(t.responses) {
		return t.responses[index], nil
	}
	return nil, fmt.Errorf("unexpected TPM command %d", index+1)
}

// sequenceTestSession is a Session whose nonceTPM, handle and validation
// result can be changed by the test.
type sequenceTestSession struct {
	handle      TPMHandle
	nonce       []byte
	validateErr error
	encrypt     bool
	decrypt     bool
}

func newSequenceTestSession() *sequenceTestSession {
	return &sequenceTestSession{
		handle: TPMHandle(0x03000001),
		nonce:  []byte{0x01, 0x02, 0x03, 0x04},
	}
}

func (s *sequenceTestSession) Init(transport.TPM) error { return nil }
func (s *sequenceTestSession) CleanupFailure(transport.TPM) error {
	return nil
}
func (s *sequenceTestSession) NewNonceCaller() error { return nil }
func (s *sequenceTestSession) Handle() TPMHandle { return s.handle }
func (s *sequenceTestSession) IsEncryption() bool { return s.encrypt }
func (s *sequenceTestSession) IsDecryption() bool { return s.decrypt }
func (s *sequenceTestSession) Encrypt([]byte) error { return nil }
func (s *sequenceTestSession) Decrypt([]byte) error { return nil }

func (s *sequenceTestSession) NonceTPM() TPM2BNonce {
	return TPM2BNonce{Buffer: cloneSequenceBytes(s.nonce)}
}

func (s *sequenceTestSession) Authorize(TPMCC, []byte, []byte, []TPM2BName, int) (*TPMSAuthCommand, error) {
	return &TPMSAuthCommand{
		Handle:     s.handle,
		Nonce:      TPM2BNonce{Buffer: []byte{0x11, 0x22}},
		Attributes: TPMASession{ContinueSession: true},
		Authorization: TPM2BData{
			Buffer: []byte{0x33},
		},
	}, nil
}

func (s *sequenceTestSession) Validate(_ TPMRC, _ TPMCC, _ []byte, _ []TPM2BName, _ int, auth *TPMSAuthResponse) error {
	if s.validateErr != nil {
		return s.validateErr
	}
	s.nonce = cloneSequenceBytes(auth.Nonce.Buffer)
	return nil
}

func encryptDecryptTestResponse(out, iv, nonce, authorization []byte) []byte {
	var params bytes.Buffer
	binary.Write(&params, binary.BigEndian, uint16(len(out)))
	params.Write(out)
	binary.Write(&params, binary.BigEndian, uint16(len(iv)))
	params.Write(iv)

	var auth bytes.Buffer
	binary.Write(&auth, binary.BigEndian, uint16(len(nonce)))
	auth.Write(nonce)
	auth.Write(attrsToBytes(TPMASession{ContinueSession: true}))
	binary.Write(&auth, binary.BigEndian, uint16(len(authorization)))
	auth.Write(authorization)

	total := 10 + 4 + params.Len() + auth.Len()
	response := make([]byte, 0, total)
	response = binary.BigEndian.AppendUint16(response, uint16(TPMSTSessions))
	response = binary.BigEndian.AppendUint32(response, uint32(total))
	response = binary.BigEndian.AppendUint32(response, uint32(TPMRCSuccess))
	response = binary.BigEndian.AppendUint32(response, uint32(params.Len()))
	response = append(response, params.Bytes()...)
	response = append(response, auth.Bytes()...)
	return response
}

func sequenceTestKey(auth Session) AuthHandle {
	return AuthHandle{
		Handle: TPMHandle(0x80000001),
		Name:   TPM2BName{Buffer: []byte{0xaa, 0xbb, 0xcc}},
		Auth:   auth,
	}
}

func sequenceTestIV(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 16)
}

func TestEncryptDecryptSequenceBindsIVAndNonce(t *testing.T) {
	session := newSequenceTestSession()
	key := sequenceTestKey(session)
	initialIV := sequenceTestIV(0x10)
	firstIV := sequenceTestIV(0x20)
	secondIV := sequenceTestIV(0x30)
	firstNonce := []byte{0x21, 0x22}
	secondNonce := []byte{0x31, 0x32}

	theTPM := &sequenceTestTPM{
		responses: [][]byte{
			encryptDecryptTestResponse([]byte("firstout"), firstIV, firstNonce, []byte{0x01}),
			encryptDecryptTestResponse([]byte("secondou"), secondIV, secondNonce, []byte{0x02}),
		},
	}
	seq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, initialIV, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}
	identity := seq.Identity()
	if identity.Handle != key.Handle || identity.Mode != TPMAlgCFB || identity.Decrypt {
		t.Errorf("initial identity = %+v, want key/mode/direction bound", identity)
	}
	if !bytes.Equal(identity.Name.Buffer, key.Name.Buffer) {
		t.Errorf("initial identity name = %x, want %x", identity.Name.Buffer, key.Name.Buffer)
	}
	if !bytes.Equal(identity.IV, initialIV) || identity.Chunk != 1 {
		t.Errorf("initial identity IV/chunk = %x/%d, want %x/1", identity.IV, identity.Chunk, initialIV)
	}

	first, err := seq.Process([]byte("firstinp"))
	if err != nil {
		t.Fatalf("first Process: %v", err)
	}
	if !bytes.Equal(first, []byte("firstout")) {
		t.Errorf("first output = %q, want %q", first, "firstout")
	}
	if !bytes.Equal(seq.IV(), firstIV) {
		t.Errorf("IV after first chunk = %x, want %x", seq.IV(), firstIV)
	}
	if !bytes.Equal(seq.SessionNonce().Buffer, firstNonce) {
		t.Errorf("nonce after first chunk = %x, want %x", seq.SessionNonce().Buffer, firstNonce)
	}
	if got := seq.Chunks(); got != 1 {
		t.Errorf("Chunks after first chunk = %d, want 1", got)
	}
	identity = seq.Identity()
	if !bytes.Equal(identity.IV, firstIV) || identity.Chunk != 2 {
		t.Errorf("identity after first chunk IV/chunk = %x/%d, want %x/2", identity.IV, identity.Chunk, firstIV)
	}
	if !bytes.Equal(identity.Nonce.Buffer, firstNonce) {
		t.Errorf("identity nonce = %x, want %x", identity.Nonce.Buffer, firstNonce)
	}

	second, err := seq.Process([]byte("secondin"))
	if err != nil {
		t.Fatalf("second Process: %v", err)
	}
	if !bytes.Equal(second, []byte("secondou")) {
		t.Errorf("second output = %q, want %q", second, "secondou")
	}
	if !bytes.Equal(seq.IV(), secondIV) {
		t.Errorf("IV after second chunk = %x, want %x", seq.IV(), secondIV)
	}
	if !bytes.Equal(seq.SessionNonce().Buffer, secondNonce) {
		t.Errorf("nonce after second chunk = %x, want %x", seq.SessionNonce().Buffer, secondNonce)
	}
	if got := seq.Chunks(); got != 2 {
		t.Errorf("Chunks after second chunk = %d, want 2", got)
	}
	identity = seq.Identity()
	if identity.Chunk != 3 {
		t.Errorf("next chunk = %d, want 3", identity.Chunk)
	}
	if got, want := seq.Committed(), []byte("firstoutsecondou"); !bytes.Equal(got, want) {
		t.Errorf("Committed = %q, want %q", got, want)
	}
	if theTPM.calls != 2 {
		t.Errorf("TPM calls = %d, want 2", theTPM.calls)
	}
	if len(theTPM.commands) != 2 {
		t.Errorf("recorded commands = %d, want 2", len(theTPM.commands))
	}
}

func TestEncryptDecryptSequenceRejectsSessionChange(t *testing.T) {
	session := newSequenceTestSession()
	key := sequenceTestKey(session)
	theTPM := &sequenceTestTPM{
		responses: [][]byte{
			encryptDecryptTestResponse([]byte("firstout"), sequenceTestIV(0x20), []byte{0x21}, []byte{0x01}),
		},
	}
	seq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, sequenceTestIV(0x10), false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}
	if _, err := seq.Process([]byte("firstinp")); err != nil {
		t.Fatalf("first Process: %v", err)
	}

	// Simulate the caller rebuilding the HMAC session before retrying the
	// failed second chunk. The sequence must notice the different session
	// identity and fail without sending the old IV to the TPM again.
	session.handle = TPMHandle(0x03000002)
	session.nonce = []byte{0x99, 0x98}
	out, err := seq.Process([]byte("secondin"))
	if err == nil {
		t.Fatal("Process after session rebuild succeeded, want failure")
	}
	if !errors.Is(err, ErrSequenceSessionChanged) {
		t.Errorf("Process error = %v, want ErrSequenceSessionChanged", err)
	}
	if !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("Process error = %v, want ErrSequenceInvalidated", err)
	}
	if out != nil {
		t.Errorf("Process returned %q after session rebuild, want nil", out)
	}
	if got := seq.Committed(); len(got) != 0 {
		t.Errorf("Committed after failure = %q, want empty", got)
	}
	if got := seq.IV(); got != nil {
		t.Errorf("IV after failure = %x, want nil", got)
	}
	if got := seq.SessionNonce().Buffer; len(got) != 0 {
		t.Errorf("SessionNonce after failure = %x, want empty", got)
	}
	if theTPM.calls != 1 {
		t.Errorf("TPM calls = %d, want 1 (the failed sequence must not reuse its old IV)", theTPM.calls)
	}
	failure := seq.Failure()
	if failure == nil {
		t.Fatal("Failure after session rebuild = nil, want audit record")
	}
	if failure.Stage != "session" {
		t.Errorf("failure stage = %q, want session", failure.Stage)
	}
	if failure.Chunk != 2 {
		t.Errorf("failure chunk = %d, want 2", failure.Chunk)
	}
	if failure.Handle != TPMHandle(0x80000001) {
		t.Errorf("failure handle = %#x, want %#x", failure.Handle, TPMHandle(0x80000001))
	}
	if !bytes.Equal(failure.Name.Buffer, key.Name.Buffer) {
		t.Errorf("failure name = %x, want %x", failure.Name.Buffer, key.Name.Buffer)
	}
	if !bytes.Equal(failure.IV, sequenceTestIV(0x20)) {
		t.Errorf("failure IV = %x, want the last authenticated IV %x", failure.IV, sequenceTestIV(0x20))
	}
	if !bytes.Equal(failure.Nonce.Buffer, []byte{0x21}) {
		t.Errorf("failure nonceTPM = %x, want 21", failure.Nonce.Buffer)
	}
	if !bytes.Equal(failure.CurrentNonce.Buffer, []byte{0x99, 0x98}) {
		t.Errorf("failure currentNonceTPM = %x, want 9998", failure.CurrentNonce.Buffer)
	}
	identity := seq.Identity()
	if identity.Chunk != 2 || !bytes.Equal(identity.IV, sequenceTestIV(0x20)) {
		t.Errorf("identity after failure chunk/IV = %d/%x, want 2/%x", identity.Chunk, identity.IV, sequenceTestIV(0x20))
	}

	// The invalidated sequence remains fail-closed and never reaches the TPM.
	if _, err := seq.Process([]byte("thirdinp")); !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("Process after invalidation = %v, want ErrSequenceInvalidated", err)
	}
	if theTPM.calls != 1 {
		t.Errorf("TPM calls after invalidated Process = %d, want 1", theTPM.calls)
	}
}

func TestEncryptDecryptSequenceDoesNotPublishUnauthenticatedOutput(t *testing.T) {
	session := newSequenceTestSession()
	session.validateErr = fmt.Errorf("%w: incorrect authorization HMAC", ErrSessionAuthorization)
	key := sequenceTestKey(session)
	theTPM := &sequenceTestTPM{
		responses: [][]byte{
			encryptDecryptTestResponse([]byte("PLAINTEXT"), sequenceTestIV(0x20), []byte{0x21}, []byte{0x99}),
		},
	}
	seq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, sequenceTestIV(0x10), true)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}

	out, err := seq.Process([]byte("secret!!!"))
	if err == nil {
		t.Fatal("Process with an invalid response HMAC succeeded, want failure")
	}
	if !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("Process error = %v, want ErrSequenceInvalidated", err)
	}
	if out != nil {
		t.Errorf("Process returned unauthenticated plaintext %q, want nil", out)
	}
	if got := seq.Committed(); len(got) != 0 {
		t.Errorf("Committed after authentication failure = %q, want empty", got)
	}
	if got := seq.IV(); got != nil {
		t.Errorf("IV after authentication failure = %x, want nil", got)
	}
	if got := seq.Chunks(); got != 0 {
		t.Errorf("Chunks after authentication failure = %d, want 0", got)
	}
	if theTPM.calls != 1 {
		t.Errorf("TPM calls = %d, want 1", theTPM.calls)
	}
	failure := seq.Failure()
	if failure == nil {
		t.Fatal("Failure after authentication failure = nil, want audit record")
	}
	if failure.Stage != "session" {
		t.Errorf("failure stage = %q, want session", failure.Stage)
	}
	if failure.Chunk != 1 {
		t.Errorf("failure chunk = %d, want 1", failure.Chunk)
	}
	if !bytes.Equal(failure.IV, sequenceTestIV(0x10)) {
		t.Errorf("failure IV = %x, want the initial IV %x", failure.IV, sequenceTestIV(0x10))
	}
	if !errors.Is(failure.Err, ErrSessionAuthorization) {
		t.Errorf("failure cause = %v, want ErrSessionAuthorization", failure.Err)
	}
}

func TestEncryptDecryptSequenceRejectsNonceReuse(t *testing.T) {
	session := newSequenceTestSession()
	theTPM := &sequenceTestTPM{
		responses: [][]byte{
			// Deliberately replay the initial nonceTPM.
			encryptDecryptTestResponse([]byte("out!"), sequenceTestIV(0x20), session.nonce, []byte{0x01}),
		},
	}
	seq, err := NewEncryptDecryptSequence(theTPM, sequenceTestKey(session), TPMAlgCFB, sequenceTestIV(0x10), false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}
	out, err := seq.Process([]byte("1234"))
	if err == nil {
		t.Fatal("Process with a non-advancing nonceTPM succeeded, want failure")
	}
	if !errors.Is(err, ErrSequenceSessionChanged) {
		t.Errorf("Process error = %v, want ErrSequenceSessionChanged", err)
	}
	if out != nil {
		t.Errorf("Process returned %q, want nil", out)
	}
	if got := seq.Committed(); len(got) != 0 {
		t.Errorf("Committed = %q, want empty", got)
	}
	failure := seq.Failure()
	if failure == nil {
		t.Fatal("Failure = nil, want audit record")
	}
	if failure.Stage != "nonce" {
		t.Errorf("failure stage = %q, want nonce", failure.Stage)
	}
	if !bytes.Equal(failure.Nonce.Buffer, session.nonce) {
		t.Errorf("failure nonceTPM = %x, want %x", failure.Nonce.Buffer, session.nonce)
	}
}

func TestEncryptDecryptSequenceProcessAllDiscardsPartialOutput(t *testing.T) {
	session := newSequenceTestSession()
	theTPM := &sequenceTestTPM{
		responses: [][]byte{
			encryptDecryptTestResponse([]byte("out1"), sequenceTestIV(0x20), []byte{0x21}, []byte{0x01}),
			nil,
		},
		errs: []error{
			nil,
			errors.New("second chunk failed"),
		},
	}
	seq, err := NewEncryptDecryptSequenceWithConfig(theTPM, EncryptDecryptSequenceConfig{
		Key:          sequenceTestKey(session),
		Mode:         TPMAlgCFB,
		IV:           sequenceTestIV(0x10),
		MaxChunkSize: 4,
	})
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequenceWithConfig: %v", err)
	}

	out, err := seq.ProcessAll([]byte("12345678"))
	if err == nil {
		t.Fatal("ProcessAll succeeded after the second chunk failed, want failure")
	}
	if !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("ProcessAll error = %v, want ErrSequenceInvalidated", err)
	}
	if out != nil {
		t.Errorf("ProcessAll returned partial output %q, want nil", out)
	}
	if got := seq.Committed(); len(got) != 0 {
		t.Errorf("Committed after failed ProcessAll = %q, want empty", got)
	}
	if got := seq.IV(); got != nil {
		t.Errorf("IV after failed ProcessAll = %x, want nil", got)
	}
	if theTPM.calls != 2 {
		t.Errorf("TPM calls = %d, want 2", theTPM.calls)
	}
	failure := seq.Failure()
	if failure == nil {
		t.Fatal("Failure after failed ProcessAll = nil, want audit record")
	}
	if failure.Stage != "tpm" {
		t.Errorf("failure stage = %q, want tpm", failure.Stage)
	}
	if failure.Chunk != 2 {
		t.Errorf("failure chunk = %d, want 2", failure.Chunk)
	}
	if !bytes.Equal(failure.IV, sequenceTestIV(0x20)) {
		t.Errorf("failure IV = %x, want %x", failure.IV, sequenceTestIV(0x20))
	}

	// Retrying the failed chunk on the same sequence must not send the old
	// IV to the TPM again.
	if _, err := seq.Process([]byte("5678")); !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("retry after failed chunk = %v, want ErrSequenceInvalidated", err)
	}
	if theTPM.calls != 2 {
		t.Errorf("TPM calls after failed-chunk retry = %d, want 2", theTPM.calls)
	}
}

func TestEncryptDecryptSequenceEmptyInput(t *testing.T) {
	theTPM := &sequenceTestTPM{}
	seq, err := NewEncryptDecryptSequence(theTPM, sequenceTestKey(newSequenceTestSession()), TPMAlgCFB, nil, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}
	out, err := seq.ProcessAll(nil)
	if err != nil {
		t.Fatalf("ProcessAll(nil): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("ProcessAll(nil) = %x, want empty", out)
	}
	if theTPM.calls != 0 {
		t.Errorf("TPM calls = %d, want 0 for empty input", theTPM.calls)
	}
	if err := seq.Err(); err != nil {
		t.Errorf("empty sequence Err() = %v, want nil", err)
	}

	if err := seq.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := seq.Process([]byte("data")); !errors.Is(err, ErrSequenceClosed) {
		t.Errorf("Process after Close = %v, want ErrSequenceClosed", err)
	}
}

func TestEncryptDecryptSequenceRejectsOversizedChunk(t *testing.T) {
	theTPM := &sequenceTestTPM{}
	seq, err := NewEncryptDecryptSequenceWithConfig(theTPM, EncryptDecryptSequenceConfig{
		Key:          sequenceTestKey(newSequenceTestSession()),
		Mode:         TPMAlgCFB,
		IV:           sequenceTestIV(0x10),
		MaxChunkSize: 4,
	})
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequenceWithConfig: %v", err)
	}

	_, err = seq.Process([]byte("12345"))
	if !errors.Is(err, ErrSequenceChunkTooLarge) {
		t.Errorf("Process oversized chunk = %v, want ErrSequenceChunkTooLarge", err)
	}
	if !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("Process oversized chunk = %v, want ErrSequenceInvalidated", err)
	}
	if theTPM.calls != 0 {
		t.Errorf("TPM calls after oversized chunk = %d, want 0", theTPM.calls)
	}
	if seq.Err() == nil {
		t.Fatal("Err after oversized chunk = nil, want failure")
	}
	failure := seq.Failure()
	if failure == nil {
		t.Fatal("Failure after oversized chunk = nil, want audit record")
	}
	if failure.Stage != "chunk" {
		t.Errorf("failure stage = %q, want chunk", failure.Stage)
	}
	if failure.Chunk != 1 {
		t.Errorf("failure chunk = %d, want 1", failure.Chunk)
	}
	if failure.Handle != TPMHandle(0x80000001) {
		t.Errorf("failure handle = %#x, want %#x", failure.Handle, TPMHandle(0x80000001))
	}
	if !bytes.Equal(failure.IV, sequenceTestIV(0x10)) {
		t.Errorf("failure IV = %x, want %x", failure.IV, sequenceTestIV(0x10))
	}
	if len(failure.Nonce.Buffer) == 0 {
		t.Error("failure nonceTPM is empty, want the bound session nonce")
	}

	if _, err := seq.Process([]byte("1234")); !errors.Is(err, ErrSequenceInvalidated) {
		t.Errorf("Process after oversized chunk = %v, want ErrSequenceInvalidated", err)
	}
	if theTPM.calls != 0 {
		t.Errorf("TPM calls after invalidated Process = %d, want 0", theTPM.calls)
	}
}

func TestEncryptDecryptSequenceRejectsMalformedIV(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		response []byte
		wantErr  error
		wantStage string
	}{
		{
			name:      "initial IV too short",
			initial:   bytes.Repeat([]byte{0x10}, 8),
			wantErr:   ErrSequenceIVInvalid,
			wantStage: "iv",
		},
		{
			name:      "empty IV",
			initial:   nil,
			wantErr:   ErrSequenceIVInvalid,
			wantStage: "iv",
		},
		{
			name:      "response IV too short",
			initial:   sequenceTestIV(0x10),
			response:  bytes.Repeat([]byte{0x20}, 8),
			wantErr:   ErrSequenceResponseInvalid,
			wantStage: "response",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			theTPM := &sequenceTestTPM{}
			if test.response != nil {
				theTPM.responses = [][]byte{
					encryptDecryptTestResponse([]byte("out!"), test.response, []byte{0x21}, []byte{0x01}),
				}
			}
			seq, err := NewEncryptDecryptSequence(theTPM, sequenceTestKey(newSequenceTestSession()), TPMAlgCFB, test.initial, false)
			if err != nil {
				t.Fatalf("NewEncryptDecryptSequence: %v", err)
			}
			if _, err := seq.Process([]byte("1234")); !errors.Is(err, test.wantErr) {
				t.Errorf("Process = %v, want %v", err, test.wantErr)
			}
			if got := seq.Committed(); len(got) != 0 {
				t.Errorf("Committed = %q, want empty", got)
			}
			failure := seq.Failure()
			if failure == nil {
				t.Fatal("Failure = nil, want audit record")
			}
			if failure.Stage != test.wantStage {
				t.Errorf("failure stage = %q, want %q", failure.Stage, test.wantStage)
			}
		})
	}
}

func TestEncryptDecryptSequenceRejectsUnsupportedMode(t *testing.T) {
	key := sequenceTestKey(newSequenceTestSession())
	iv := sequenceTestIV(0x10)
	_, err := NewEncryptDecryptSequence(&sequenceTestTPM{}, key, TPMAlgSHA256, iv, false)
	if !errors.Is(err, ErrUnsupportedMode) {
		t.Errorf("NewEncryptDecryptSequence error = %v, want ErrUnsupportedMode", err)
	}
	failure, ok := err.(*SequenceFailure)
	if !ok {
		t.Fatalf("NewEncryptDecryptSequence error type = %T, want *SequenceFailure", err)
	}
	if failure.Stage != "mode" {
		t.Errorf("failure stage = %q, want mode", failure.Stage)
	}
	if failure.Handle != key.Handle {
		t.Errorf("failure handle = %#x, want %#x", failure.Handle, key.Handle)
	}
	if !bytes.Equal(failure.IV, iv) {
		t.Errorf("failure IV = %x, want %x", failure.IV, iv)
	}
	if !bytes.Equal(failure.Name.Buffer, key.Name.Buffer) {
		t.Errorf("failure name = %x, want %x", failure.Name.Buffer, key.Name.Buffer)
	}
}
