package tpm2test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func createAESSequenceKey(theTPM transport.TPM, mode TPMAlgID) (AuthHandle, func(), error) {
	primary, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgSymCipher,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgSymCipher,
				&TPMSSymCipherParms{
					Sym: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						Mode:      NewTPMUSymMode(TPMAlgAES, mode),
						KeyBits: NewTPMUSymKeyBits(
							TPMAlgAES,
							TPMKeyBits(128),
						),
					},
				},
			),
		}),
	}.Execute(theTPM)
	if err != nil {
		return AuthHandle{}, nil, err
	}
	cleanup := func() {
		_, _ = (FlushContext{FlushHandle: primary.ObjectHandle}).Execute(theTPM)
	}
	return AuthHandle{
		Handle: primary.ObjectHandle,
		Name:   primary.Name,
		Auth:   PasswordAuth(nil),
	}, cleanup, nil
}

func randomSequenceBytes(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		t.Fatalf("reading random bytes: %v", err)
	}
	return out
}

func TestEncryptDecryptSequenceMatchesSingleCall(t *testing.T) {
	theTPM := testhelper.Open(t)
	t.Cleanup(func() {
		if err := theTPM.Close(); err != nil {
			t.Errorf("closing TPM: %v", err)
		}
	})

	key, cleanup, err := createAESSequenceKey(theTPM, TPMAlgCFB)
	if err != nil {
		t.Fatalf("creating AES-CFB key: %v", err)
	}
	t.Cleanup(cleanup)

	message := randomSequenceBytes(t, DefaultEncryptDecryptChunkSize*2)
	iv := randomSequenceBytes(t, 16)

	// The first chunk of a sequence must be byte-for-byte identical to the
	// old single-call API for the same key, mode and IV.
	single, err := EncryptDecrypt2{
		KeyHandle: key,
		Message: TPM2BMaxBuffer{
			Buffer: message[:DefaultEncryptDecryptChunkSize],
		},
		Decrypt: false,
		Mode:    TPMAlgCFB,
		IV: TPM2BIV{
			Buffer: iv,
		},
	}.Execute(theTPM)
	if err != nil {
		t.Fatalf("single-call EncryptDecrypt2: %v", err)
	}

	encrypted, err := EncryptDecryptAll(theTPM, key, TPMAlgCFB, iv, message, false)
	if err != nil {
		t.Fatalf("EncryptDecryptAll encryption: %v", err)
	}
	if len(encrypted) < DefaultEncryptDecryptChunkSize {
		t.Fatalf("encrypted sequence has %d bytes, want at least %d", len(encrypted), DefaultEncryptDecryptChunkSize)
	}
	if !bytes.Equal(encrypted[:DefaultEncryptDecryptChunkSize], single.OutData.Buffer) {
		t.Errorf("first sequence chunk differs from single-call EncryptDecrypt2")
	}
	if len(encrypted) != len(message) {
		t.Errorf("encrypted sequence has %d bytes, want %d", len(encrypted), len(message))
	}

	decrypted, err := EncryptDecryptAll(theTPM, key, TPMAlgCFB, iv, encrypted, true)
	if err != nil {
		t.Fatalf("EncryptDecryptAll decryption: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("round trip mismatch")
	}

	empty, err := EncryptDecryptAll(theTPM, key, TPMAlgCFB, nil, nil, false)
	if err != nil {
		t.Fatalf("EncryptDecryptAll(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("EncryptDecryptAll(empty) = %x, want empty", empty)
	}
}

func TestEncryptDecryptSequenceHMACSession(t *testing.T) {
	theTPM := testhelper.Open(t)
	t.Cleanup(func() {
		if err := theTPM.Close(); err != nil {
			t.Errorf("closing TPM: %v", err)
		}
	})

	key, cleanup, err := createAESSequenceKey(theTPM, TPMAlgCFB)
	if err != nil {
		t.Fatalf("creating AES-CFB key: %v", err)
	}
	t.Cleanup(cleanup)

	session, closeSession, err := HMACSession(theTPM, TPMAlgSHA256, 16, Auth(nil))
	if err != nil {
		t.Fatalf("creating HMAC session: %v", err)
	}
	t.Cleanup(func() {
		if err := closeSession(); err != nil {
			t.Errorf("closing HMAC session: %v", err)
		}
	})
	key.Auth = session

	message := randomSequenceBytes(t, DefaultEncryptDecryptChunkSize*2)
	iv := randomSequenceBytes(t, 16)
	seq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, iv, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}

	nonceBefore := append([]byte(nil), session.NonceTPM().Buffer...)
	first, err := seq.Process(message[:DefaultEncryptDecryptChunkSize])
	if err != nil {
		t.Fatalf("first Process: %v", err)
	}
	nonceAfter := session.NonceTPM()
	if bytes.Equal(nonceBefore, nonceAfter.Buffer) {
		t.Errorf("session nonceTPM did not change after an authenticated chunk")
	}
	if !bytes.Equal(seq.SessionNonce().Buffer, nonceAfter.Buffer) {
		t.Errorf("sequence nonce = %x, want session nonce %x", seq.SessionNonce().Buffer, nonceAfter.Buffer)
	}

	second, err := seq.Process(message[DefaultEncryptDecryptChunkSize:])
	if err != nil {
		t.Fatalf("second Process: %v", err)
	}
	if got := seq.Chunks(); got != 2 {
		t.Errorf("Chunks = %d, want 2", got)
	}

	decryptSeq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, iv, true)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence for decryption: %v", err)
	}
	decrypted, err := decryptSeq.ProcessAll(append(first, second...))
	if err != nil {
		t.Fatalf("decrypting sequence: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("HMAC-session round trip mismatch")
	}
}

func TestEncryptDecryptSequenceHMACParameterEncryption(t *testing.T) {
	theTPM := testhelper.Open(t)
	t.Cleanup(func() {
		if err := theTPM.Close(); err != nil {
			t.Errorf("closing TPM: %v", err)
		}
	})

	key, cleanup, err := createAESSequenceKey(theTPM, TPMAlgCFB)
	if err != nil {
		t.Fatalf("creating AES-CFB key: %v", err)
	}
	t.Cleanup(cleanup)

	// Use the session for both object authorization and parameter
	// encryption/decryption. This exercises the KDFa nonce chain in
	// hmacSession.Encrypt/Decrypt in addition to the data IV chain.
	session, closeSession, err := HMACSession(theTPM, TPMAlgSHA256, 16, Auth(nil), AESEncryption(128, EncryptInOut))
	if err != nil {
		t.Fatalf("creating HMAC parameter-encryption session: %v", err)
	}
	t.Cleanup(func() {
		if err := closeSession(); err != nil {
			t.Errorf("closing HMAC parameter-encryption session: %v", err)
		}
	})
	key.Auth = session

	message := randomSequenceBytes(t, DefaultEncryptDecryptChunkSize*2)
	iv := randomSequenceBytes(t, 16)
	encryptSeq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, iv, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}
	nonceBefore := append([]byte(nil), session.NonceTPM().Buffer...)
	encrypted, err := encryptSeq.ProcessAll(message)
	if err != nil {
		t.Fatalf("encrypting with parameter encryption: %v", err)
	}
	nonceAfter := session.NonceTPM()
	if bytes.Equal(nonceBefore, nonceAfter.Buffer) {
		t.Error("session nonceTPM did not advance during parameter-encrypted chunking")
	}
	if !bytes.Equal(encryptSeq.SessionNonce().Buffer, nonceAfter.Buffer) {
		t.Errorf("sequence nonce = %x, want session nonce %x", encryptSeq.SessionNonce().Buffer, nonceAfter.Buffer)
	}
	if len(encrypted) != len(message) {
		t.Fatalf("encrypted length = %d, want %d", len(encrypted), len(message))
	}

	decryptSeq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, iv, true)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence for decryption: %v", err)
	}
	decrypted, err := decryptSeq.ProcessAll(encrypted)
	if err != nil {
		t.Fatalf("decrypting with parameter encryption: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("parameter-encryption round trip mismatch")
	}
	if len(decryptSeq.SessionNonce().Buffer) == 0 {
		t.Error("decrypt sequence has no session nonceTPM binding")
	}
}

// switchableSession lets a test replace the session underlying an AuthHandle
// without changing the AuthHandle held by an EncryptDecryptSequence.
type switchableSession struct {
	inner Session
}

func (s *switchableSession) swap(inner Session) {
	s.inner = inner
}

func (s *switchableSession) Init(t transport.TPM) error { return s.inner.Init(t) }
func (s *switchableSession) CleanupFailure(t transport.TPM) error {
	return s.inner.CleanupFailure(t)
}
func (s *switchableSession) NonceTPM() TPM2BNonce { return s.inner.NonceTPM() }
func (s *switchableSession) NewNonceCaller() error { return s.inner.NewNonceCaller() }
func (s *switchableSession) Handle() TPMHandle { return s.inner.Handle() }
func (s *switchableSession) IsEncryption() bool { return s.inner.IsEncryption() }
func (s *switchableSession) IsDecryption() bool { return s.inner.IsDecryption() }
func (s *switchableSession) Encrypt(b []byte) error { return s.inner.Encrypt(b) }
func (s *switchableSession) Decrypt(b []byte) error { return s.inner.Decrypt(b) }
func (s *switchableSession) Authorize(cc TPMCC, parms, addNonces []byte, names []TPM2BName, authIndex int) (*TPMSAuthCommand, error) {
	return s.inner.Authorize(cc, parms, addNonces, names, authIndex)
}
func (s *switchableSession) Validate(rc TPMRC, cc TPMCC, parms []byte, names []TPM2BName, authIndex int, auth *TPMSAuthResponse) error {
	return s.inner.Validate(rc, cc, parms, names, authIndex, auth)
}

type countingTPM struct {
	tpm   transport.TPM
	calls int
}

func (t *countingTPM) Send(input []byte) ([]byte, error) {
	t.calls++
	return t.tpm.Send(input)
}

func TestEncryptDecryptSequenceRejectsSessionRebuild(t *testing.T) {
	theTPM := testhelper.Open(t)
	t.Cleanup(func() {
		if err := theTPM.Close(); err != nil {
			t.Errorf("closing TPM: %v", err)
		}
	})

	key, cleanup, err := createAESSequenceKey(theTPM, TPMAlgCFB)
	if err != nil {
		t.Fatalf("creating AES-CFB key: %v", err)
	}
	t.Cleanup(cleanup)

	// The sessions also parameter-encrypt the data, so rebuilding one changes
	// both the KDFa nonce chain and the sequence's authorization identity.
	firstSession, closeFirst, err := HMACSession(theTPM, TPMAlgSHA256, 16, Auth(nil), AESEncryption(128, EncryptInOut))
	if err != nil {
		t.Fatalf("creating first HMAC session: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFirst(); err != nil {
			t.Errorf("closing first HMAC session: %v", err)
		}
	})
	wrapped := &switchableSession{inner: firstSession}
	key.Auth = wrapped

	counter := &countingTPM{tpm: theTPM}
	message := randomSequenceBytes(t, DefaultEncryptDecryptChunkSize*2)
	iv := randomSequenceBytes(t, 16)
	seq, err := NewEncryptDecryptSequence(counter, key, TPMAlgCFB, iv, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence: %v", err)
	}

	if _, err := seq.Process(message[:DefaultEncryptDecryptChunkSize]); err != nil {
		t.Fatalf("first Process: %v", err)
	}
	if counter.calls != 1 {
		t.Fatalf("TPM calls after first chunk = %d, want 1", counter.calls)
	}
	firstIV := seq.IV()

	secondSession, closeSecond, err := HMACSession(theTPM, TPMAlgSHA256, 16, Auth(nil), AESEncryption(128, EncryptInOut))
	if err != nil {
		t.Fatalf("creating rebuilt HMAC session: %v", err)
	}
	t.Cleanup(func() {
		if err := closeSecond(); err != nil {
			t.Errorf("closing rebuilt HMAC session: %v", err)
		}
	})
	wrapped.swap(secondSession)

	out, err := seq.Process(message[DefaultEncryptDecryptChunkSize:])
	if err == nil {
		t.Fatal("Process after session rebuild succeeded, want failure")
	}
	if !errors.Is(err, ErrSequenceSessionChanged) {
		t.Errorf("Process error = %v, want ErrSequenceSessionChanged", err)
	}
	if out != nil {
		t.Errorf("Process after session rebuild returned %x, want nil", out)
	}
	if got := seq.Committed(); len(got) != 0 {
		t.Errorf("Committed after session rebuild = %x, want empty", got)
	}
	if got := seq.IV(); got != nil {
		t.Errorf("IV after session rebuild = %x, want nil", got)
	}
	if counter.calls != 1 {
		t.Errorf("TPM calls after session rebuild = %d, want 1 (old IV must not be reused)", counter.calls)
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
	if !bytes.Equal(failure.IV, firstIV) {
		t.Errorf("failure IV = %x, want first chunk's output IV %x", failure.IV, firstIV)
	}

	// A safe retry uses a brand-new sequence with a fresh IV and the rebuilt
	// session. It must not continue the old IV sequence.
	retryIV := randomSequenceBytes(t, 16)
	retry, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, retryIV, false)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence retry: %v", err)
	}
	reencrypted, err := retry.ProcessAll(message)
	if err != nil {
		t.Fatalf("retry ProcessAll: %v", err)
	}
	decryptSeq, err := NewEncryptDecryptSequence(theTPM, key, TPMAlgCFB, retryIV, true)
	if err != nil {
		t.Fatalf("NewEncryptDecryptSequence retry decryption: %v", err)
	}
	decrypted, err := decryptSeq.ProcessAll(reencrypted)
	if err != nil {
		t.Fatalf("retry decryption: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("fresh-session retry round trip mismatch")
	}
}

func TestEncryptDecryptSequenceModesAndChunking(t *testing.T) {
	theTPM := testhelper.Open(t)
	t.Cleanup(func() {
		if err := theTPM.Close(); err != nil {
			t.Errorf("closing TPM: %v", err)
		}
	})

	cases := []struct {
		name    string
		keyMode TPMAlgID
		cmdMode TPMAlgID
		sizes   []int
	}{
		{
			name:    "CFB",
			keyMode: TPMAlgCFB,
			cmdMode: TPMAlgCFB,
			sizes:   []int{0, 1, 15, 16, 17, DefaultEncryptDecryptChunkSize - 1, DefaultEncryptDecryptChunkSize, DefaultEncryptDecryptChunkSize + 1, DefaultEncryptDecryptChunkSize * 2},
		},
		{
			name:    "CTR",
			keyMode: TPMAlgCTR,
			cmdMode: TPMAlgCTR,
			sizes:   []int{0, 1, 16, 17, DefaultEncryptDecryptChunkSize + 1},
		},
		{
			name:    "OFB",
			keyMode: TPMAlgOFB,
			cmdMode: TPMAlgOFB,
			sizes:   []int{0, 1, 16, 17, DefaultEncryptDecryptChunkSize + 1},
		},
		{
			name:    "CBC",
			keyMode: TPMAlgCBC,
			cmdMode: TPMAlgCBC,
			sizes:   []int{0, 16, 32, DefaultEncryptDecryptChunkSize, DefaultEncryptDecryptChunkSize * 2},
		},
		{
			name:    "ECB",
			keyMode: TPMAlgECB,
			cmdMode: TPMAlgECB,
			sizes:   []int{0, 16, 32, DefaultEncryptDecryptChunkSize, DefaultEncryptDecryptChunkSize * 2},
		},
		{
			name:    "NullUsesKeyMode",
			keyMode: TPMAlgCFB,
			cmdMode: TPMAlgNull,
			sizes:   []int{0, 1, 16, DefaultEncryptDecryptChunkSize + 1},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			key, cleanup, err := createAESSequenceKey(theTPM, test.keyMode)
			if err != nil {
				if errors.Is(err, TPMRCMode) || errors.Is(err, TPMRCSymmetric) || errors.Is(err, TPMRCKey) || errors.Is(err, TPMRCValue) {
					t.Skipf("TPM does not support AES-%v: %v", test.keyMode, err)
				}
				t.Fatalf("creating AES-%v key: %v", test.keyMode, err)
			}
			t.Cleanup(cleanup)

			for _, size := range test.sizes {
				message := randomSequenceBytes(t, size)
				iv := randomSequenceBytes(t, 16)

				encrypted, err := EncryptDecryptAll(theTPM, key, test.cmdMode, iv, message, false)
				if err != nil {
					if errors.Is(err, TPMRCMode) || errors.Is(err, TPMRCSymmetric) || errors.Is(err, TPMRCKey) {
						t.Skipf("TPM does not support %v with size %d: %v", test.cmdMode, size, err)
					}
					if test.cmdMode != TPMAlgCFB && (errors.Is(err, TPMRCValue) || errors.Is(err, TPMRCSize)) {
						t.Skipf("TPM does not support %v with size %d and a 16-byte IV: %v", test.cmdMode, size, err)
					}
					t.Fatalf("encrypting %v size %d: %v", test.cmdMode, size, err)
				}
				decrypted, err := EncryptDecryptAll(theTPM, key, test.cmdMode, iv, encrypted, true)
				if err != nil {
					t.Fatalf("decrypting %v size %d: %v", test.cmdMode, size, err)
				}
				if !bytes.Equal(decrypted, message) {
					t.Errorf("%v size %d round trip mismatch", test.cmdMode, size)
				}
			}
		})
	}
}
