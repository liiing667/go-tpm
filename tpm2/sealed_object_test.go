// Copyright (c) 2026, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

func sealedObjectTestParts(t *testing.T) (*AuthHandle, TPM2BPublic, TPM2BPrivate, TPM2BName) {
	t.Helper()
	template := TPMTPublic{
		Type:    TPMAlgKeyedHash,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: NewTPMUPublicParms(TPMAlgKeyedHash, &TPMSKeyedHashParms{}),
		Unique: NewTPMUPublicID(
			TPMAlgKeyedHash,
			&TPM2BDigest{},
		),
	}
	name, err := ObjectName(&template)
	if err != nil {
		t.Fatalf("ObjectName() = %v", err)
	}
	parent := &AuthHandle{
		Handle: TPMHandle(0x80000000),
		Name:   TPM2BName{Buffer: append([]byte(nil), name.Buffer...)},
		Auth:   PasswordAuth(nil),
	}
	return parent, New2B(template), TPM2BPrivate{Buffer: []byte{1, 2, 3}}, *name
}

func TestSealedObjectTransactionSnapshot(t *testing.T) {
	parent, public, private, name := sealedObjectTestParts(t)

	plaintext := []byte("sealed plaintext")
	auth := []byte("object password")
	policy := bytes.Repeat([]byte{0x5a}, 32)

	sealed, err := NewSealedObject(parent, public, private, name, plaintext, auth, policy)
	if err != nil {
		t.Fatalf("NewSealedObject() = %v", err)
	}
	if !bytes.Equal(sealed.Name.Buffer, name.Buffer) {
		t.Errorf("Name = %x, want %x", sealed.Name.Buffer, name.Buffer)
	}
	if !bytes.Equal(sealed.Public.Bytes(), public.Bytes()) {
		t.Errorf("Public = %x, want %x", sealed.Public.Bytes(), public.Bytes())
	}
	if !bytes.Equal(sealed.Plaintext, plaintext) {
		t.Errorf("Plaintext = %x, want %x", sealed.Plaintext, plaintext)
	}
	if !bytes.Equal(sealed.Auth, auth) {
		t.Errorf("Auth = %x, want %x", sealed.Auth, auth)
	}
	if !bytes.Equal(sealed.Policy.Buffer, policy) {
		t.Errorf("Policy = %x, want %x", sealed.Policy.Buffer, policy)
	}

	// The transaction must own its byte slices; changing the caller's inputs
	// must not change the sealed object or its old blob.
	plaintext[0] ^= 0xff
	auth[0] ^= 0xff
	policy[0] ^= 0xff
	private.Buffer[0] ^= 0xff
	if !bytes.Equal(sealed.Plaintext, []byte("sealed plaintext")) {
		t.Errorf("Plaintext changed through caller buffer: %x", sealed.Plaintext)
	}
	if !bytes.Equal(sealed.Private.Buffer, []byte{1, 2, 3}) {
		t.Errorf("Private changed through caller buffer: %x", sealed.Private.Buffer)
	}
}

func TestSealedObjectTransactionRejectsNameMismatch(t *testing.T) {
	parent, public, private, name := sealedObjectTestParts(t)
	name.Buffer[0] ^= 0xff
	_, err := NewSealedObject(parent, public, private, name, []byte("data"), nil, nil)
	if !errors.Is(err, ErrSealedObjectName) {
		t.Fatalf("NewSealedObject() = %v, want ErrSealedObjectName", err)
	}
}

type sealedObjectPanicTPM struct{}

func (sealedObjectPanicTPM) Send([]byte) ([]byte, error) {
	panic("TPM must not be called for an empty private area")
}

func TestSealedObjectTransactionRejectsEmptyPrivateBeforeTPM(t *testing.T) {
	parent, public, _, name := sealedObjectTestParts(t)
	if _, err := NewSealedObject(parent, public, TPM2BPrivate{}, name, []byte("data"), nil, nil); !errors.Is(err, ErrSealedObjectPrivate) {
		t.Fatalf("NewSealedObject(empty private) = %v, want ErrSealedObjectPrivate", err)
	}

	// A transaction assembled directly (for example, deserialized by a
	// caller) is also rejected at Load time before the TPM is touched.
	sealed := &SealedObject{
		Parent:    parent,
		Public:    public,
		Name:      name,
		Plaintext: []byte("data"),
	}
	var tpm transport.TPM = sealedObjectPanicTPM{}
	if _, err := sealed.Load(tpm); !errors.Is(err, ErrSealedObjectPrivate) {
		t.Fatalf("Load() = %v, want ErrSealedObjectPrivate", err)
	}
}
