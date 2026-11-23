package tpm2

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// DefaultEncryptDecryptChunkSize is the maximum number of bytes sent in a
	// single TPM2_EncryptDecrypt2 call. TPM2B_MAX_BUFFER is limited to
	// MAX_DIGEST_BUFFER (1024) bytes by the TPM 2.0 specification.
	DefaultEncryptDecryptChunkSize = 1024
)

var (
	// ErrSequenceInvalidated indicates that an encrypt/decrypt sequence can no
	// longer be used. A sequence is invalidated after any TPM, session,
	// response, IV or input validation failure.
	ErrSequenceInvalidated = errors.New("tpm2: encrypt/decrypt sequence invalidated")
	// ErrSequenceClosed indicates that the sequence was closed by the caller.
	ErrSequenceClosed = errors.New("tpm2: encrypt/decrypt sequence closed")
	// ErrSequenceSessionChanged indicates that the session bound to the
	// sequence changed (for example, it was rebuilt or its nonceTPM moved)
	// between two chunks.
	ErrSequenceSessionChanged = errors.New("tpm2: encrypt/decrypt session changed")
	// ErrSequenceChunkTooLarge indicates that a caller supplied more data than
	// MaxChunkSize. Process fails closed because the sequence cannot safely
	// resume from an unsent chunk; use ProcessAll to split input automatically.
	ErrSequenceChunkTooLarge = errors.New("tpm2: encrypt/decrypt chunk too large")
	// ErrSequenceIVInvalid indicates that an IV did not have the size required
	// by the selected mode.
	ErrSequenceIVInvalid = errors.New("tpm2: encrypt/decrypt IV invalid")
	// ErrSequenceResponseInvalid indicates that a TPM response was not a valid
	// continuation of the sequence.
	ErrSequenceResponseInvalid = errors.New("tpm2: encrypt/decrypt response invalid")
)

// SequenceFailure is the auditable record of the chunk that invalidated an
// EncryptDecryptSequence. It retains the object handle, mode, direction, input
// IV, one-based chunk number, last authenticated session nonceTPM and failure
// stage. It never contains plaintext.
type SequenceFailure struct {
	Handle  TPMHandle
	// Name is the TPM Name of the object authenticated for the sequence.
	Name    TPM2BName
	Mode    TPMIAlgSymMode
	Decrypt bool
	// IV is the chaining value supplied to the failed chunk.
	IV []byte
	// Chunk is the one-based number of the failed chunk.
	Chunk int
	// Nonce is the last authenticated session nonceTPM before the failure.
	Nonce TPM2BNonce
	// CurrentNonce is the session nonceTPM observed at the failure point. It
	// differs from Nonce when a rebuilt session or replayed nonce is rejected.
	CurrentNonce TPM2BNonce
	// Stage identifies where the sequence failed, for example "iv",
	// "session", "tpm", "response", "nonce" or "chunk".
	Stage string
	// Err is the underlying failure.
	Err error
}

// SequenceIdentity is the immutable object, mode and direction binding of an
// EncryptDecryptSequence together with the current IV, session nonceTPM and
// one-based number of the next chunk.
type SequenceIdentity struct {
	Handle  TPMHandle
	Name    TPM2BName
	Mode    TPMIAlgSymMode
	Decrypt bool
	IV      []byte
	Nonce   TPM2BNonce
	// CurrentNonce is the session nonceTPM currently exposed by the session.
	CurrentNonce TPM2BNonce
	Chunk   int
}

// Error implements error.
func (f *SequenceFailure) Error() string {
	if f == nil {
		return ErrSequenceInvalidated.Error()
	}
	cause := ""
	if f.Err != nil {
		cause = ": " + f.Err.Error()
	}
	return fmt.Sprintf("%v at %s for handle %#x name=%x chunk %d (iv=%x nonceTPM=%x currentNonceTPM=%x)%s",
		ErrSequenceInvalidated, f.Stage, f.Handle, f.Name.Buffer, f.Chunk, f.IV, f.Nonce.Buffer, f.CurrentNonce.Buffer, cause)
}

// Unwrap makes errors.Is work for both ErrSequenceInvalidated and the
// underlying failure.
func (f *SequenceFailure) Unwrap() []error {
	if f == nil {
		return []error{ErrSequenceInvalidated}
	}
	if f.Err == nil {
		return []error{ErrSequenceInvalidated}
	}
	return []error{ErrSequenceInvalidated, f.Err}
}

// EncryptDecryptSequenceConfig configures an EncryptDecryptSequence.
type EncryptDecryptSequenceConfig struct {
	// Key is the loaded symmetric key used by TPM2_EncryptDecrypt2. Its Auth
	// session is part of the sequence identity and must not change while the
	// sequence is active. A reusable HMAC session (see HMACSession) is
	// required to process more than one chunk.
	Key AuthHandle
	// Mode is the symmetric mode. TPMAlgNull selects the mode of the key.
	Mode TPMIAlgSymMode
	// IV is the initial chaining value. It is copied by the constructor.
	IV []byte
	// Decrypt selects decryption instead of encryption.
	Decrypt bool
	// MaxChunkSize is the largest amount of data sent in one
	// TPM2_EncryptDecrypt2 call. Zero selects
	// DefaultEncryptDecryptChunkSize.
	MaxChunkSize int
}

// EncryptDecryptSequence is one continuous TPM2_EncryptDecrypt2 sequence.
//
// A sequence binds together the key object, mode, direction, IV, authorization
// session (including its nonceTPM), chunk results and the caller consuming
// them. Each chunk is sent only with the IV returned by the authenticated
// previous chunk. Chunk output is returned only after TPM2_EncryptDecrypt2
// (including the response session HMAC) has been validated by Execute.
//
// Any failure invalidates the sequence: the current IV, session nonce and
// committed output are discarded and no further TPM command is sent. In
// particular, a failed chunk cannot be retried with the old IV or with a
// rebuilt session on the same sequence. To retry, construct a new sequence
// with a fresh IV and, if the old session was rebuilt, the new session.
//
// The sequence does not own the key or the authorization session. The caller
// remains responsible for flushing them.
type EncryptDecryptSequence struct {
	mu sync.Mutex

	key          AuthHandle
	mode         TPMIAlgSymMode
	decrypt      bool
	maxChunkSize int

	// iv is the chaining value to be used by the next chunk.
	iv []byte
	// committed contains output from chunks that were authenticated and
	// accepted. It is cleared whenever the sequence fails.
	committed []byte
	chunks    int

	// failed is set once the sequence cannot continue. The first error is
	// retained so every later operation reports the failure that invalidated
	// the sequence.
	failed  error
	failure *SequenceFailure
	closed  bool

	// boundHandle and boundNonce are the session identity after the last
	// authenticated chunk. checkBinding is false only before the first chunk
	// of a just-in-time session that has no handle yet.
	boundHandle      TPMHandle
	boundNonce       TPM2BNonce
	checkBinding     bool
	sessionExhausted bool

	// execute is injectable for tests. Production code uses the real
	// TPM2_EncryptDecrypt2 command.
	execute func(EncryptDecrypt2) (*EncryptDecrypt2Response, error)
}

// NewEncryptDecryptSequence starts one continuous TPM2_EncryptDecrypt2
// sequence. The initial IV and the current session nonceTPM are copied into the
// sequence.
func NewEncryptDecryptSequence(t transport.TPM, key AuthHandle, mode TPMIAlgSymMode, iv []byte, decrypt bool) (*EncryptDecryptSequence, error) {
	return NewEncryptDecryptSequenceWithConfig(t, EncryptDecryptSequenceConfig{
		Key:     key,
		Mode:    mode,
		IV:      iv,
		Decrypt: decrypt,
	})
}

// NewEncryptDecryptSequenceWithConfig starts one continuous
// TPM2_EncryptDecrypt2 sequence using cfg.
func NewEncryptDecryptSequenceWithConfig(t transport.TPM, cfg EncryptDecryptSequenceConfig) (*EncryptDecryptSequence, error) {
	if t == nil {
		return nil, fmt.Errorf("tpm2: encrypt/decrypt sequence requires a transport")
	}
	if cfg.Key.Auth == nil {
		return nil, fmt.Errorf("tpm2: encrypt/decrypt sequence requires a key authorization session")
	}
	if err := validateEncryptDecryptMode(cfg.Mode); err != nil {
		return nil, newConfigSequenceFailure(cfg, "mode", err)
	}
	maxChunkSize := cfg.MaxChunkSize
	if maxChunkSize == 0 {
		maxChunkSize = DefaultEncryptDecryptChunkSize
	}
	if maxChunkSize < 0 || maxChunkSize > DefaultEncryptDecryptChunkSize {
		err := fmt.Errorf("%w: invalid chunk size %d; want 1..%d", ErrSequenceChunkTooLarge, maxChunkSize, DefaultEncryptDecryptChunkSize)
		return nil, newConfigSequenceFailure(cfg, "chunk", err)
	}

	key := cfg.Key
	key.Name = TPM2BName{Buffer: cloneSequenceBytes(key.Name.Buffer)}

	seq := &EncryptDecryptSequence{
		key:          key,
		mode:         cfg.Mode,
		decrypt:      cfg.Decrypt,
		maxChunkSize: maxChunkSize,
		iv:           cloneSequenceBytes(cfg.IV),
	}
	seq.boundHandle = key.Auth.Handle()
	seq.boundNonce = cloneSequenceNonce(key.Auth.NonceTPM())
	// A just-in-time session (for example, the one returned by HMAC) does not
	// have a handle before its first command. Once it has one, every following
	// chunk must use exactly that same session identity.
	seq.checkBinding = seq.boundHandle != TPMRHNull
	seq.execute = func(cmd EncryptDecrypt2) (*EncryptDecrypt2Response, error) {
		return cmd.Execute(t)
	}
	return seq, nil
}

// Process encrypts or decrypts one chunk. The chunk must be at most
// MaxChunkSize bytes. Output is returned only after the TPM response and its
// session authorization have been validated. If the caller needs one
// all-or-nothing plaintext result for a multi-chunk message, use ProcessAll.
// A failed chunk invalidates the sequence and records a SequenceFailure with
// the handle, IV, chunk number, nonceTPM and failure stage.
//
// A zero-length input is a no-op and returns an empty slice without contacting
// the TPM.
func (s *EncryptDecryptSequence) Process(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSequenceClosed
	}
	if s.failed != nil {
		return nil, s.failed
	}
	if len(data) == 0 {
		return []byte{}, nil
	}
	if len(data) > s.maxChunkSize {
		return nil, s.failAtLocked("chunk", fmt.Errorf("%w: %d bytes > %d", ErrSequenceChunkTooLarge, len(data), s.maxChunkSize))
	}
	return s.processLocked(data)
}

// ProcessAll encrypts or decrypts data as one sequence, splitting it into
// chunks of at most MaxChunkSize bytes. It returns output only if every chunk
// succeeds. If any chunk fails, the sequence is invalidated, all partial output
// is discarded, and nil is returned with the error.
//
// A zero-length input is a no-op and returns an empty slice without contacting
// the TPM.
func (s *EncryptDecryptSequence) ProcessAll(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSequenceClosed
	}
	if s.failed != nil {
		return nil, s.failed
	}
	if len(data) == 0 {
		return []byte{}, nil
	}
	if s.maxChunkSize <= 0 {
		return nil, s.failAtLocked("chunk", fmt.Errorf("%w: invalid chunk size %d", ErrSequenceChunkTooLarge, s.maxChunkSize))
	}
	chunkSize := s.maxChunkSize
	if s.mode == TPMAlgCBC || s.mode == TPMAlgECB {
		chunkSize -= chunkSize % aes.BlockSize
		if chunkSize == 0 {
			return nil, s.failAtLocked("chunk", fmt.Errorf("%w: %d bytes cannot hold one %v block", ErrSequenceChunkTooLarge, s.maxChunkSize, s.mode))
		}
	}

	out := make([]byte, 0, len(data))
	for rest := data; len(rest) > 0; {
		n := len(rest)
		if n > chunkSize {
			n = chunkSize
		}
		chunk, err := s.processLocked(rest[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		rest = rest[n:]
	}
	return out, nil
}

// EncryptDecryptAll encrypts or decrypts data as one continuous sequence and
// returns the complete result. It is a convenience wrapper around
// EncryptDecryptSequence. It never resumes a failed sequence; a retry must use
// a new sequence with a fresh IV and a rebuilt session when applicable.
func EncryptDecryptAll(t transport.TPM, key AuthHandle, mode TPMIAlgSymMode, iv, data []byte, decrypt bool) ([]byte, error) {
	seq, err := NewEncryptDecryptSequence(t, key, mode, iv, decrypt)
	if err != nil {
		return nil, err
	}
	return seq.ProcessAll(data)
}

// processLocked processes one chunk. s.mu must be held by the caller.
func (s *EncryptDecryptSequence) processLocked(data []byte) ([]byte, error) {
	if s.key.Auth == nil {
		return nil, s.failAtLocked("auth", fmt.Errorf("tpm2: encrypt/decrypt sequence has no authorization session"))
	}
	if err := validateEncryptDecryptIV(s.mode, s.iv); err != nil {
		return nil, s.failAtLocked("iv", err)
	}
	if s.sessionExhausted {
		return nil, s.failAtLocked("session", fmt.Errorf("%w: the session cannot continue the sequence", ErrSequenceSessionChanged))
	}
	if s.checkBinding {
		if err := s.checkSessionBindingLocked(); err != nil {
			return nil, s.failAtLocked("session", err)
		}
	}
	if s.execute == nil {
		return nil, s.failAtLocked("executor", fmt.Errorf("tpm2: encrypt/decrypt sequence has no command executor"))
	}

	cmd := EncryptDecrypt2{
		KeyHandle: s.key,
		Message: TPM2BMaxBuffer{
			Buffer: cloneSequenceBytes(data),
		},
		Decrypt: s.decrypt,
		Mode:    s.mode,
		IV: TPM2BIV{
			Buffer: cloneSequenceBytes(s.iv),
		},
	}
	rsp, err := s.execute(cmd)
	if err != nil {
		stage := "tpm"
		if errors.Is(err, ErrSessionAuthorization) {
			stage = "session"
		}
		return nil, s.failAtLocked(stage, fmt.Errorf("executing TPM2_EncryptDecrypt2: %w", err))
	}
	if rsp == nil {
		return nil, s.failAtLocked("response", fmt.Errorf("%w: nil TPM response", ErrSequenceResponseInvalid))
	}
	if len(rsp.OutData.Buffer) != len(data) {
		return nil, s.failAtLocked("response", fmt.Errorf("%w: got %d output bytes for %d input bytes", ErrSequenceResponseInvalid, len(rsp.OutData.Buffer), len(data)))
	}
	if err := validateEncryptDecryptResponseIV(s.mode, s.iv, rsp.IV.Buffer); err != nil {
		return nil, s.failAtLocked("response", err)
	}

	out := cloneSequenceBytes(rsp.OutData.Buffer)
	newIV := cloneSequenceBytes(rsp.IV.Buffer)
	newHandle := s.key.Auth.Handle()
	newNonce := cloneSequenceNonce(s.key.Auth.NonceTPM())
	if s.checkBinding && newHandle != s.boundHandle && newHandle != TPMRHNull {
		return nil, s.failAtLocked("session", fmt.Errorf("%w: session handle changed during TPM command", ErrSequenceSessionChanged))
	}
	if s.checkBinding && len(s.boundNonce.Buffer) != 0 && bytes.Equal(newNonce.Buffer, s.boundNonce.Buffer) {
		return nil, s.failAtLocked("nonce", fmt.Errorf("%w: session nonceTPM did not advance", ErrSequenceSessionChanged))
	}

	// Commit the chunk only after the TPM response was accepted. In
	// particular, a later chunk failure clears committed so a caller
	// using Committed or ProcessAll never observes unauthenticated or
	// partial plaintext.
	s.iv = newIV
	s.committed = append(s.committed, out...)
	s.chunks++

	s.boundHandle = newHandle
	s.boundNonce = newNonce
	s.checkBinding = true
	if s.boundHandle == TPMRHNull {
		// The session was flushed by the TPM (for example, a one-off
		// HMAC session). Continuing would silently create a new session
		// while reusing the old IV sequence.
		s.sessionExhausted = true
	}
	return out, nil
}

// checkSessionBindingLocked verifies that the authorization session is still
// the same session that produced the last authenticated chunk. s.mu must be
// held by the caller.
func (s *EncryptDecryptSequence) checkSessionBindingLocked() error {
	handle := s.key.Auth.Handle()
	nonce := s.key.Auth.NonceTPM()
	if handle != s.boundHandle {
		return fmt.Errorf("%w: session handle changed from %#x to %#x", ErrSequenceSessionChanged, s.boundHandle, handle)
	}
	if !bytes.Equal(nonce.Buffer, s.boundNonce.Buffer) {
		return fmt.Errorf("%w: session nonceTPM changed", ErrSequenceSessionChanged)
	}
	return nil
}

// failAtLocked invalidates the sequence and records err with the sequence
// state that produced it. s.mu must be held by the caller.
func (s *EncryptDecryptSequence) failAtLocked(stage string, err error) error {
	if s.failed != nil {
		return s.failed
	}
	var currentNonce TPM2BNonce
	if s.key.Auth != nil {
		currentNonce = cloneSequenceNonce(s.key.Auth.NonceTPM())
	}
	failure := &SequenceFailure{
		Handle:  s.key.Handle,
		Name:    cloneSequenceName(s.key.Name),
		Mode:    s.mode,
		Decrypt: s.decrypt,
		IV:      cloneSequenceBytes(s.iv),
		Chunk:   s.chunks + 1,
		Nonce:   cloneSequenceNonce(s.boundNonce),
		CurrentNonce: currentNonce,
		Stage:   stage,
		Err:     err,
	}
	s.failure = failure
	s.failed = failure
	s.iv = nil
	s.committed = nil
	s.chunks = 0
	s.boundNonce = TPM2BNonce{}
	s.sessionExhausted = true
	return s.failed
}

// IV returns a copy of the IV that will be used by the next chunk. It returns
// nil once the sequence has failed or has been closed.
func (s *EncryptDecryptSequence) IV() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil || s.closed {
		return nil
	}
	return cloneSequenceBytes(s.iv)
}

// SessionNonce returns a copy of the session nonceTPM that is bound to the
// next chunk. This is the same nonceTPM that hmacSession.Encrypt/Decrypt feed
// into KDFa for session parameter encryption. It returns an empty nonce once
// the sequence has failed or has been closed.
func (s *EncryptDecryptSequence) SessionNonce() TPM2BNonce {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil || s.closed {
		return TPM2BNonce{}
	}
	return cloneSequenceNonce(s.boundNonce)
}

// Committed returns the output of all authenticated chunks in this sequence.
// It returns an empty slice after a failure.
func (s *EncryptDecryptSequence) Committed() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSequenceBytes(s.committed)
}

// Chunks returns the number of authenticated chunks in this sequence.
func (s *EncryptDecryptSequence) Chunks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chunks
}

// Err returns the error that invalidated the sequence, or nil if it is still
// active.
func (s *EncryptDecryptSequence) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// Failure returns a copy of the audit record that invalidated the sequence, or
// nil if the sequence is still active. The record includes the object handle,
// mode, input IV, one-based chunk number, last authenticated nonceTPM and
// failure stage; it does not contain plaintext.
func (s *EncryptDecryptSequence) Failure() *SequenceFailure {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure == nil {
		return nil
	}
	failure := *s.failure
	failure.Name = cloneSequenceName(failure.Name)
	failure.IV = cloneSequenceBytes(failure.IV)
	failure.Nonce = cloneSequenceNonce(failure.Nonce)
	failure.CurrentNonce = cloneSequenceNonce(failure.CurrentNonce)
	return &failure
}

// Identity returns the object, mode, direction, IV, session nonceTPM and next
// chunk number currently bound to the sequence. After a failure, it returns the
// identity captured in the SequenceFailure instead of the cleared live state.
func (s *EncryptDecryptSequence) Identity() SequenceIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return SequenceIdentity{
			Handle:  s.failure.Handle,
			Name:    cloneSequenceName(s.failure.Name),
			Mode:    s.failure.Mode,
			Decrypt: s.failure.Decrypt,
			IV:      cloneSequenceBytes(s.failure.IV),
			Nonce:   cloneSequenceNonce(s.failure.Nonce),
			CurrentNonce: cloneSequenceNonce(s.failure.CurrentNonce),
			Chunk:   s.failure.Chunk,
		}
	}
	var currentNonce TPM2BNonce
	if s.key.Auth != nil {
		currentNonce = cloneSequenceNonce(s.key.Auth.NonceTPM())
	}
	return SequenceIdentity{
		Handle:  s.key.Handle,
		Name:    cloneSequenceName(s.key.Name),
		Mode:    s.mode,
		Decrypt: s.decrypt,
		IV:      cloneSequenceBytes(s.iv),
		Nonce:   cloneSequenceNonce(s.boundNonce),
		CurrentNonce: currentNonce,
		Chunk:   s.chunks + 1,
	}
}

// Close discards the sequence state. It does not flush the key or the
// authorization session. A closed sequence cannot be reused.
func (s *EncryptDecryptSequence) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.iv = nil
	s.committed = nil
	s.chunks = 0
	s.boundNonce = TPM2BNonce{}
	return nil
}

func validateEncryptDecryptMode(mode TPMIAlgSymMode) error {
	switch mode {
	case TPMAlgNull, TPMAlgCFB, TPMAlgCTR, TPMAlgOFB, TPMAlgCBC, TPMAlgECB:
		return nil
	default:
		return fmt.Errorf("%w: %v", ErrUnsupportedMode, mode)
	}
}

func validateEncryptDecryptIV(mode TPMIAlgSymMode, iv []byte) error {
	switch mode {
	case TPMAlgCFB, TPMAlgCTR, TPMAlgOFB, TPMAlgCBC:
		if len(iv) != aes.BlockSize {
			return fmt.Errorf("%w: %v IV is %d bytes, want %d", ErrSequenceIVInvalid, mode, len(iv), aes.BlockSize)
		}
	case TPMAlgECB:
		// ECB does not chain, but the TPM still encodes the IV parameter.
		if len(iv) != 0 && len(iv) != aes.BlockSize {
			return fmt.Errorf("%w: %v IV is %d bytes, want 0 or %d", ErrSequenceIVInvalid, mode, len(iv), aes.BlockSize)
		}
	}
	return nil
}

func validateEncryptDecryptResponseIV(mode TPMIAlgSymMode, inputIV, outputIV []byte) error {
	switch mode {
	case TPMAlgCFB, TPMAlgCTR, TPMAlgOFB, TPMAlgCBC:
		if len(outputIV) != aes.BlockSize {
			return fmt.Errorf("%w: %v returned a %d-byte IV, want %d", ErrSequenceResponseInvalid, mode, len(outputIV), aes.BlockSize)
		}
	case TPMAlgECB:
		if len(outputIV) != 0 && len(outputIV) != aes.BlockSize {
			return fmt.Errorf("%w: %v returned a %d-byte IV", ErrSequenceResponseInvalid, mode, len(outputIV))
		}
	case TPMAlgNull:
		// The mode belongs to the key. The TPM must return the same
		// width of chaining value that was supplied, so a key-mode change
		// cannot silently reset the sequence.
		if len(outputIV) != len(inputIV) {
			return fmt.Errorf("%w: TPM returned a %d-byte IV for a %d-byte input IV", ErrSequenceResponseInvalid, len(outputIV), len(inputIV))
		}
	}
	return nil
}

func cloneSequenceBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneSequenceNonce(n TPM2BNonce) TPM2BNonce {
	return TPM2BNonce{Buffer: cloneSequenceBytes(n.Buffer)}
}

func cloneSequenceName(n TPM2BName) TPM2BName {
	return TPM2BName{Buffer: cloneSequenceBytes(n.Buffer)}
}

func newConfigSequenceFailure(cfg EncryptDecryptSequenceConfig, stage string, err error) *SequenceFailure {
	var nonce TPM2BNonce
	if cfg.Key.Auth != nil {
		nonce = cloneSequenceNonce(cfg.Key.Auth.NonceTPM())
	}
	return &SequenceFailure{
		Handle:       cfg.Key.Handle,
		Name:         cloneSequenceName(cfg.Key.Name),
		Mode:         cfg.Mode,
		Decrypt:      cfg.Decrypt,
		IV:           cloneSequenceBytes(cfg.IV),
		Chunk:        1,
		Nonce:        cloneSequenceNonce(nonce),
		CurrentNonce: cloneSequenceNonce(nonce),
		Stage:        stage,
		Err:          err,
	}
}
