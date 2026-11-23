package tpm2test

import (
	"bytes"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// TestCredentialChallengeTransaction checks that the EK public area, AK Name,
// credential blob, secret and activation result remain one transaction. A
// failed first activation followed by an attempt with another AK must not
// consume the secret, while retrying with the committed AK still succeeds.
func TestCredentialChallengeTransaction(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for _, ekTest := range []struct {
		name string
		pub  TPMTPublic
	}{
		{name: "ECC EK", pub: ECCEKTemplate},
		{name: "RSA EK", pub: RSAEKTemplate},
	} {
		t.Run(ekTest.name, func(t *testing.T) {
			ek, err := CreatePrimary{
				PrimaryHandle: TPMRHEndorsement,
				InPublic:      New2B(ekTest.pub),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("creating EK: %v", err)
			}
			defer FlushContext{FlushHandle: ek.ObjectHandle}.Execute(thetpm)

			akECC, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(ECCSRKTemplate),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("creating ECC AK: %v", err)
			}
			defer FlushContext{FlushHandle: akECC.ObjectHandle}.Execute(thetpm)

			akRSA, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(RSASRKTemplate),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("creating RSA AK: %v", err)
			}
			defer FlushContext{FlushHandle: akRSA.ObjectHandle}.Execute(thetpm)

			ekAuth := func() AuthHandle {
				return AuthHandle{
					Handle: ek.ObjectHandle,
					Name:   ek.Name,
					Auth:   Policy(TPMAlgSHA256, 16, ekPolicy),
				}
			}
			ekNamed := NamedHandle{Handle: ek.ObjectHandle, Name: ek.Name}
			akECCNamed := NamedHandle{Handle: akECC.ObjectHandle, Name: akECC.Name}
			akRSANamed := NamedHandle{Handle: akRSA.ObjectHandle, Name: akRSA.Name}

			for _, credential := range []struct {
				name  string
				value []byte
			}{
				{name: "non-empty", value: []byte("credential")},
				{name: "empty", value: nil},
			} {
				t.Run(credential.name, func(t *testing.T) {
					challenge, err := MakeCredentialChallenge(thetpm, ekNamed, akECC.Name.Buffer, credential.value)
					if err != nil {
						t.Fatalf("MakeCredentialChallenge() = %v", err)
					}

					// The first activation uses the committed AK but bad
					// authorization, so it fails at the TPM without
					// invalidating the challenge.
					badAKAuth := AuthHandle{
						Handle: akECC.ObjectHandle,
						Name:   akECC.Name,
						Auth:   PasswordAuth([]byte("wrong")),
					}
					if _, err := challenge.Activate(thetpm, ekAuth(), badAKAuth); err == nil {
						t.Fatal("Activate() with wrong AK authorization succeeded")
					}

					// Retrying with another AK must fail on identity, not
					// consume the first AK's secret.
					if _, err := challenge.Activate(thetpm, ekAuth(), akRSANamed); !errors.Is(err, ErrCredentialChallengeIdentity) {
						t.Fatalf("Activate(other AK) error = %v, want ErrCredentialChallengeIdentity", err)
					}

					// The committed AK can still consume its own
					// challenge.
					result, err := challenge.Activate(thetpm, ekAuth(), akECCNamed)
					if err != nil {
						t.Fatalf("Activate(committed AK) = %v", err)
					}
					if !bytes.Equal(result.CertInfo.Buffer, credential.value) {
						t.Fatalf("activated credential = %x, want %x", result.CertInfo.Buffer, credential.value)
					}

					if _, err := challenge.Activate(thetpm, ekAuth(), akECCNamed); !errors.Is(err, ErrCredentialChallengeConsumed) {
						t.Fatalf("second Activate() error = %v, want ErrCredentialChallengeConsumed", err)
					}

					restored, err := RestoreCredentialChallenge(challenge.Snapshot())
					if err != nil {
						t.Fatalf("RestoreCredentialChallenge() = %v", err)
					}
					if _, err := restored.Activate(thetpm, ekAuth(), akECCNamed); !errors.Is(err, ErrCredentialChallengeConsumed) {
						t.Fatalf("restored Activate() error = %v, want ErrCredentialChallengeConsumed", err)
					}
				})
			}
		})
	}

	t.Run("valid P384 AK name", func(t *testing.T) {
		ek, err := CreatePrimary{
			PrimaryHandle: TPMRHEndorsement,
			InPublic:      New2B(ECCEKTemplate),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("creating EK: %v", err)
		}
		defer FlushContext{FlushHandle: ek.ObjectHandle}.Execute(thetpm)

		ak, err := CreatePrimary{
			PrimaryHandle: TPMRHOwner,
			InPublic:      New2B(p384Template),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("creating P384 AK: %v", err)
		}
		defer FlushContext{FlushHandle: ak.ObjectHandle}.Execute(thetpm)

		credential := []byte("p384 credential")
		challenge, err := MakeCredentialChallenge(
			thetpm,
			NamedHandle{Handle: ek.ObjectHandle, Name: ek.Name},
			ak.Name.Buffer,
			credential,
		)
		if err != nil {
			t.Fatalf("MakeCredentialChallenge() = %v", err)
		}
		result, err := challenge.Activate(
			thetpm,
			AuthHandle{
				Handle: ek.ObjectHandle,
				Name:   ek.Name,
				Auth:   Policy(TPMAlgSHA256, 16, ekPolicy),
			},
			NamedHandle{Handle: ak.ObjectHandle, Name: ak.Name},
		)
		if err != nil {
			t.Fatalf("Activate(P384 AK) = %v", err)
		}
		if !bytes.Equal(result.CertInfo.Buffer, credential) {
			t.Fatalf("activated credential = %x, want %x", result.CertInfo.Buffer, credential)
		}
	})
}
