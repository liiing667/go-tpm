package tpm2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func testCredentialName(fill byte) TPM2BName {
	name := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(name[:2], uint16(TPMAlgSHA256))
	for i := 2; i < len(name); i++ {
		name[i] = fill
	}
	return TPM2BName{Buffer: name}
}

func testCredentialBlob() TPM2BIDObject {
	// TPMS_ID_OBJECT: a SHA-256 integrity HMAC followed by an encrypted
	// TPM2B_DIGEST. The encrypted identity is opaque to the client.
	blob := make([]byte, 2+sha256.Size+2)
	binary.BigEndian.PutUint16(blob[:2], sha256.Size)
	return TPM2BIDObject{Buffer: blob}
}

func testCredentialChallenge() *CredentialChallenge {
	ekName := testCredentialName(0x11)
	akName := testCredentialName(0x22)
	credential := []byte("credential")
	c := &CredentialChallenge{
		ekName:           ekName,
		akName:           akName,
		credential:       credential,
		credentialDigest: sha256.Sum256(credential),
		blob:             testCredentialBlob(),
		secret:           TPM2BEncryptedSecret{Buffer: []byte{1, 2, 3, 4}},
		state:            CredentialChallengeReady,
	}
	c.ekPublicBytes = []byte("canonical EK public area")
	c.ekPublicDigest = sha256.Sum256(c.ekPublicBytes)
	c.id = c.computeID()
	return c
}

func TestCredentialChallengeStateValues(t *testing.T) {
	if CredentialChallengeReady != 0 ||
		CredentialChallengeActivated != 1 ||
		CredentialChallengeFailed != 2 {
		t.Fatalf("unexpected challenge state values: %d, %d, %d",
			CredentialChallengeReady, CredentialChallengeActivated, CredentialChallengeFailed)
	}
	if CredentialChallengeSucceeded != CredentialChallengeActivated ||
		ChallengeSucceeded != CredentialChallengeActivated {
		t.Fatal("succeeded aliases do not match activated state")
	}
}

func TestCredentialChallengeRejectsDifferentAK(t *testing.T) {
	c := testCredentialChallenge()
	ek := NamedHandle{Handle: 0x80000001, Name: c.ekName}
	otherAK := NamedHandle{Handle: 0x80000002, Name: testCredentialName(0x33)}

	if _, err := c.Activate(nil, ek, otherAK); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("Activate() error = %v, want ErrCredentialChallengeIdentity", err)
	}
	if got := c.State(); got != CredentialChallengeReady {
		t.Fatalf("state after identity mismatch = %v, want ready", got)
	}
	attempts := c.Attempts()
	if len(attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(attempts))
	}
	if attempts[0].Stage != "validate_ak" {
		t.Fatalf("failure stage = %q, want validate_ak", attempts[0].Stage)
	}
	if attempts[0].SecretDigest != sha256.Sum256(c.secret.Buffer) {
		t.Fatal("attempt did not retain the secret digest")
	}
}

func TestCredentialChallengeRejectsDifferentEK(t *testing.T) {
	c := testCredentialChallenge()
	otherEK := NamedHandle{Handle: 0x80000003, Name: testCredentialName(0x44)}
	ak := NamedHandle{Handle: 0x80000002, Name: c.akName}

	if _, err := c.Activate(nil, otherEK, ak); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("Activate() error = %v, want ErrCredentialChallengeIdentity", err)
	}
}

func TestCredentialChallengeRejectsOtherBlobOrSecret(t *testing.T) {
	c := testCredentialChallenge()
	ek := NamedHandle{Handle: 0x80000001, Name: c.ekName}
	ak := NamedHandle{Handle: 0x80000002, Name: c.akName}
	otherBlob := TPM2BIDObject{Buffer: testCredentialBlob().Buffer}
	otherBlob.Buffer[2] ^= 0xff
	if _, err := c.ActivateWithBlob(nil, ek, ak, otherBlob, c.Secret()); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("ActivateWithBlob(other blob) error = %v, want ErrCredentialChallengeIdentity", err)
	}
	otherSecret := TPM2BEncryptedSecret{Buffer: []byte{9, 9, 9}}
	if _, err := c.ActivateWithBlob(nil, ek, ak, c.CredentialBlob(), otherSecret); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("ActivateWithBlob(other secret) error = %v, want ErrCredentialChallengeIdentity", err)
	}
}

func TestCredentialChallengeConsumed(t *testing.T) {
	c := testCredentialChallenge()
	c.state = CredentialChallengeActivated
	ek := NamedHandle{Handle: 0x80000001, Name: c.ekName}
	ak := NamedHandle{Handle: 0x80000002, Name: c.akName}

	if _, err := c.Activate(nil, ek, ak); !errors.Is(err, ErrCredentialChallengeConsumed) {
		t.Fatalf("Activate() error = %v, want ErrCredentialChallengeConsumed", err)
	}
	if _, err := c.ActivateWithBlob(nil, ek, ak, c.CredentialBlob(), c.Secret()); !errors.Is(err, ErrCredentialChallengeConsumed) {
		t.Fatalf("ActivateWithBlob() error = %v, want ErrCredentialChallengeConsumed", err)
	}
}

func TestCredentialChallengeSnapshotChecksum(t *testing.T) {
	c := testCredentialChallenge()
	snapshot := c.Snapshot()
	if snapshot.Checksum != credentialChallengeChecksum(snapshot) {
		t.Fatal("snapshot checksum does not verify")
	}
	snapshot.AKName[2] ^= 0xff
	if _, err := RestoreCredentialChallenge(snapshot); !errors.Is(err, ErrCredentialChallengeSnapshot) {
		t.Fatalf("RestoreCredentialChallenge() error = %v, want ErrCredentialChallengeSnapshot", err)
	}
}

func TestCredentialChallengeSaveLoadPreservesConsumedState(t *testing.T) {
	public := ECCEKTemplate
	challenge, err := newCredentialChallenge(&public, testCredentialName(0x22), []byte("credential"), testCredentialBlob().Buffer, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("newCredentialChallenge() = %v", err)
	}
	ek := NamedHandle{Handle: 0x80000001, Name: challenge.EKName()}
	wrongAK := NamedHandle{Handle: 0x80000003, Name: testCredentialName(0x33)}
	if _, err := challenge.Activate(nil, ek, wrongAK); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("Activate(other AK) error = %v, want ErrCredentialChallengeIdentity", err)
	}
	challenge.state = CredentialChallengeActivated

	var encoded bytes.Buffer
	if err := challenge.Save(&encoded); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	restored, err := LoadCredentialChallenge(&encoded)
	if err != nil {
		t.Fatalf("LoadCredentialChallenge() = %v", err)
	}
	if restored.State() != CredentialChallengeActivated {
		t.Fatalf("restored state = %v, want activated", restored.State())
	}
	if attempts := restored.Attempts(); len(attempts) != 1 || attempts[0].Stage != "validate_ak" {
		t.Fatalf("restored attempts = %+v, want one validate_ak attempt", attempts)
	}
	ek = NamedHandle{Handle: 0x80000001, Name: restored.EKName()}
	ak := NamedHandle{Handle: 0x80000002, Name: restored.AKName()}
	if _, err := restored.Activate(nil, ek, ak); !errors.Is(err, ErrCredentialChallengeConsumed) {
		t.Fatalf("restored Activate() error = %v, want ErrCredentialChallengeConsumed", err)
	}

	var trailing bytes.Buffer
	if err := challenge.Save(&trailing); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	trailing.WriteString("{}\n")
	if _, err := LoadCredentialChallenge(&trailing); !errors.Is(err, ErrCredentialChallengeSnapshot) {
		t.Fatalf("LoadCredentialChallenge(trailing data) error = %v, want ErrCredentialChallengeSnapshot", err)
	}
}

func TestCredentialChallengeVerifyIdentity(t *testing.T) {
	public := ECCEKTemplate
	akName := testCredentialName(0x22)
	challenge, err := newCredentialChallenge(&public, akName, []byte("credential"), testCredentialBlob().Buffer, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("newCredentialChallenge() = %v", err)
	}
	if err := challenge.VerifyEKPublic(&public); err != nil {
		t.Fatalf("VerifyEKPublic() = %v", err)
	}
	otherPublic := ECCSRKTemplate
	if err := challenge.VerifyEKPublic(&otherPublic); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("VerifyEKPublic(other) error = %v, want ErrCredentialChallengeIdentity", err)
	}
	if err := challenge.VerifyAKName(akName); err != nil {
		t.Fatalf("VerifyAKName() = %v", err)
	}
	if err := challenge.VerifyAKName(testCredentialName(0x23)); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("VerifyAKName(other) error = %v, want ErrCredentialChallengeIdentity", err)
	}
}

func TestNewCredentialChallengeSoftware(t *testing.T) {
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ECC key: %v", err)
	}
	ecdhPoint := ecdhKey.PublicKey().Bytes()
	ecPublic := ECCEKTemplate
	ecPublic.Unique = NewTPMUPublicID(TPMAlgECC, &TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: ecdhPoint[1:33]},
		Y: TPM2BECCParameter{Buffer: ecdhPoint[33:]},
	})

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	rsaPublic := RSAEKTemplate
	rsaPublic.Unique = NewTPMUPublicID(TPMAlgRSA, &TPM2BPublicKeyRSA{Buffer: rsaKey.N.Bytes()})

	for _, tc := range []struct {
		name   string
		public *TPMTPublic
	}{
		{name: "ECDH", public: &ecPublic},
		{name: "RSA", public: &rsaPublic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, credential := range [][]byte{[]byte("credential"), nil} {
				akName := testCredentialName(0x22)
				challenge, err := NewCredentialChallenge(rand.Reader, tc.public, akName.Buffer, credential)
				if err != nil {
					t.Fatalf("NewCredentialChallenge() = %v", err)
				}
				fromBytes, err := NewCredentialChallengeFromPublicBytes(rand.Reader, Marshal(*tc.public), akName.Buffer, credential)
				if err != nil {
					t.Fatalf("NewCredentialChallengeFromPublicBytes() = %v", err)
				}
				if err := challenge.VerifyEKPublic(tc.public); err != nil {
					t.Fatalf("VerifyEKPublic() = %v", err)
				}
				if !bytes.Equal(challenge.EKName().Buffer, fromBytes.EKName().Buffer) {
					t.Fatalf("serialized EK public area changed the EK Name: %x != %x",
						challenge.EKName().Buffer, fromBytes.EKName().Buffer)
				}
				if err := challenge.VerifyAKName(akName); err != nil {
					t.Fatalf("VerifyAKName() = %v", err)
				}
				ek := NamedHandle{Handle: 0x80000001, Name: challenge.EKName()}
				wrongAK := NamedHandle{Handle: 0x80000002, Name: testCredentialName(0x33)}
				if _, err := challenge.Activate(nil, ek, wrongAK); !errors.Is(err, ErrCredentialChallengeIdentity) {
					t.Fatalf("Activate(other AK) error = %v, want ErrCredentialChallengeIdentity", err)
				}
			}
		})
	}
}

func TestValidateCredentialPublicName(t *testing.T) {
	public := ECCSRKTemplate
	name, err := ObjectName(&public)
	if err != nil {
		t.Fatalf("ObjectName() = %v", err)
	}
	if err := validateCredentialPublicName(New2B(public), *name); err != nil {
		t.Fatalf("valid public area rejected: %v", err)
	}
	tampered := testCredentialName(9)
	if err := validateCredentialPublicName(New2B(public), tampered); !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("tampered public Name error = %v, want ErrCredentialChallengeIdentity", err)
	}
}

func TestValidateCredentialObjectName(t *testing.T) {
	if err := validateCredentialObjectName(testCredentialName(1)); err != nil {
		t.Fatalf("valid Name rejected: %v", err)
	}
	if err := validateCredentialObjectName(TPM2BName{}); !errors.Is(err, ErrCredentialChallengeName) {
		t.Fatalf("empty Name error = %v, want ErrCredentialChallengeName", err)
	}
	short := testCredentialName(1)
	short.Buffer = short.Buffer[:len(short.Buffer)-1]
	if err := validateCredentialObjectName(short); !errors.Is(err, ErrCredentialChallengeName) {
		t.Fatalf("short Name error = %v, want ErrCredentialChallengeName", err)
	}
}

type credentialTestKey struct{}

func (credentialTestKey) Encapsulate(io.Reader, string) ([]byte, []byte, error) {
	return make([]byte, 32), make([]byte, 32), nil
}

func (credentialTestKey) NameAlg() TPMAlgID { return TPMAlgSHA256 }

func (credentialTestKey) SymmetricParameters() *TPMTSymDefObject {
	return &TPMTSymDefObject{
		Algorithm: TPMAlgAES,
		KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(128)),
		Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
	}
}

func TestCreateCredentialRejectsUnboundName(t *testing.T) {
	if _, _, err := CreateCredential(rand.Reader, credentialTestKey{}, nil, []byte("credential")); !errors.Is(err, ErrCredentialChallengeName) {
		t.Fatalf("CreateCredential(empty name) error = %v, want ErrCredentialChallengeName", err)
	}
}

func TestCreateCredentialAllowsEmptyCredential(t *testing.T) {
	idObject, secret, err := CreateCredential(rand.Reader, credentialTestKey{}, testCredentialName(1).Buffer, nil)
	if err != nil {
		t.Fatalf("CreateCredential() = %v", err)
	}
	if len(idObject) == 0 || len(secret) == 0 {
		t.Fatalf("CreateCredential() returned empty output: blob=%d secret=%d", len(idObject), len(secret))
	}
	if err := validateCredentialBlob(TPM2BIDObject{Buffer: idObject}); err != nil {
		t.Fatalf("empty credential produced invalid blob: %v", err)
	}
}

type credentialTestTPM struct{}

func (credentialTestTPM) Send([]byte) ([]byte, error) {
	panic("TPM command must not be sent for invalid credential parameters")
}

type credentialTestResponse struct {
	response []byte
}

func (t credentialTestResponse) Send([]byte) ([]byte, error) {
	return t.response, nil
}

type credentialSequenceTPM struct {
	responses [][]byte
	calls     int
}

func (t *credentialSequenceTPM) Send([]byte) ([]byte, error) {
	if t.calls >= len(t.responses) {
		return nil, errors.New("unexpected TPM command")
	}
	response := t.responses[t.calls]
	t.calls++
	return response, nil
}

func credentialTestWire(t *testing.T, handles, parameters []byte) []byte {
	t.Helper()
	size := 10 + len(handles) + len(parameters)
	wire := make([]byte, size)
	binary.BigEndian.PutUint16(wire[:2], uint16(TPMSTNoSessions))
	binary.BigEndian.PutUint32(wire[2:6], uint32(size))
	copy(wire[10:], handles)
	copy(wire[10+len(handles):], parameters)
	return wire
}

func credentialReadPublicWire(t *testing.T, public TPM2BPublic, name TPM2BName) []byte {
	t.Helper()
	rsp := ReadPublicResponse{OutPublic: public, Name: name}
	preimage, err := MarshalResponse[ReadPublic, ReadPublicResponse](ReadPublic{}, &rsp)
	if err != nil {
		t.Fatalf("MarshalResponse() = %v", err)
	}
	return credentialTestWire(t, nil, preimage[8:])
}

func TestReadPublicRejectsMismatchedName(t *testing.T) {
	public := ECCSRKTemplate
	name, err := ObjectName(&public)
	if err != nil {
		t.Fatalf("ObjectName() = %v", err)
	}
	for _, tc := range []struct {
		name    string
		rspName TPM2BName
		wantErr bool
	}{
		{name: "matching", rspName: *name},
		{name: "mismatched", rspName: testCredentialName(9), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rsp := ReadPublicResponse{
				OutPublic: New2B(public),
				Name:      tc.rspName,
			}
			preimage, err := MarshalResponse[ReadPublic, ReadPublicResponse](ReadPublic{}, &rsp)
			if err != nil {
				t.Fatalf("MarshalResponse() = %v", err)
			}
			wire := credentialTestWire(t, nil, preimage[8:])
			_, err = (ReadPublic{ObjectHandle: TPMHandle(0x80000001)}).Execute(credentialTestResponse{response: wire})
			if tc.wantErr {
				if !errors.Is(err, ErrCredentialChallengeIdentity) {
					t.Fatalf("ReadPublic() error = %v, want ErrCredentialChallengeIdentity", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadPublic() = %v", err)
			}
		})
	}
}

func TestCredentialChallengeRejectsActualHandleIdentityChange(t *testing.T) {
	ekPublic := ECCEKTemplate
	akName, err := ObjectName(&ECCSRKTemplate)
	if err != nil {
		t.Fatalf("ObjectName(ECC SRK) = %v", err)
	}
	challenge, err := newCredentialChallenge(&ekPublic, *akName, []byte("credential"), testCredentialBlob().Buffer, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("newCredentialChallenge() = %v", err)
	}

	ekName, err := ObjectName(&ekPublic)
	if err != nil {
		t.Fatalf("ObjectName(EK) = %v", err)
	}
	otherAKName, err := ObjectName(&RSASRKTemplate)
	if err != nil {
		t.Fatalf("ObjectName(RSA SRK) = %v", err)
	}
	tpm := &credentialSequenceTPM{responses: [][]byte{
		credentialReadPublicWire(t, New2B(ekPublic), *ekName),
		credentialReadPublicWire(t, New2B(RSASRKTemplate), *otherAKName),
	}}
	_, err = challenge.Activate(
		tpm,
		NamedHandle{Handle: 0x80000001, Name: challenge.EKName()},
		NamedHandle{Handle: 0x80000002, Name: challenge.AKName()},
	)
	if !errors.Is(err, ErrCredentialChallengeIdentity) {
		t.Fatalf("Activate() error = %v, want ErrCredentialChallengeIdentity", err)
	}
	if tpm.calls != 2 {
		t.Fatalf("TPM calls = %d, want 2 ReadPublic calls and no ActivateCredential", tpm.calls)
	}
	attempts := challenge.Attempts()
	if len(attempts) != 1 || attempts[0].Stage != "validate_ak" {
		t.Fatalf("attempts = %+v, want one validate_ak attempt", attempts)
	}
}

func TestMakeCredentialRejectsInvalidNameBeforeTPM(t *testing.T) {
	_, err := (MakeCredential{
		Credential: TPM2BDigest{Buffer: []byte("credential")},
		ObjectName: TPM2BName{},
	}).Execute(credentialTestTPM{})
	if !errors.Is(err, ErrCredentialChallengeName) {
		t.Fatalf("MakeCredential(invalid Name) error = %v, want ErrCredentialChallengeName", err)
	}
	_, err = (MakeCredential{
		Credential: TPM2BDigest{Buffer: make([]byte, 65536)},
		ObjectName: testCredentialName(1),
	}).Execute(credentialTestTPM{})
	if !errors.Is(err, ErrCredentialChallengeCredential) {
		t.Fatalf("MakeCredential(oversized credential) error = %v, want ErrCredentialChallengeCredential", err)
	}
}

func TestActivateCredentialRejectsInvalidBlobBeforeTPM(t *testing.T) {
	ek := NamedHandle{Handle: 0x80000001, Name: testCredentialName(0x11)}
	ak := NamedHandle{Handle: 0x80000002, Name: testCredentialName(0x22)}
	_, err := (ActivateCredential{
		ActivateHandle: ak,
		KeyHandle:      ek,
		CredentialBlob: TPM2BIDObject{},
		Secret:         TPM2BEncryptedSecret{Buffer: []byte{1}},
	}).Execute(credentialTestTPM{})
	if !errors.Is(err, ErrCredentialChallengeBlob) {
		t.Fatalf("ActivateCredential(invalid blob) error = %v, want ErrCredentialChallengeBlob", err)
	}
}
