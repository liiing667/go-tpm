package tpm2test

import (
	"bytes"
	"crypto/rand"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestMigrationSoftwareDuplicateImport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template TPMTPublic
	}{
		{name: "ECDH-P256", template: ECCSRKTemplate},
		{name: "RSA-2048", template: RSASRKTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			thetpm := testhelper.Open(t)
			defer thetpm.Close()

			parent, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(tc.template),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("CreatePrimary() = %v", err)
			}
			defer FlushContext{FlushHandle: parent.ObjectHandle}.Execute(thetpm)

			parentPublic, err := parent.OutPublic.Contents()
			if err != nil {
				t.Fatalf("parent.OutPublic.Contents() = %v", err)
			}
			key, err := ImportEncapsulationKey(parentPublic)
			if err != nil {
				t.Fatalf("ImportEncapsulationKey() = %v", err)
			}

			plaintext := []byte("migration transaction")
			sealedPublic, sealedPrivate := makeSealedBlob(t, TPMAlgSHA256, make([]byte, 32), plaintext)
			sealedName, err := ObjectName(sealedPublic)
			if err != nil {
				t.Fatalf("ObjectName() = %v", err)
			}
			duplicate, seed, err := CreateDuplicate(rand.Reader, key, sealedName.Buffer, sealedPrivate)
			if err != nil {
				t.Fatalf("CreateDuplicate() = %v", err)
			}

			migration, err := NewMigration(
				AuthHandle{
					Handle: parent.ObjectHandle,
					Name:   parent.Name,
					Auth:   PasswordAuth(nil),
				},
				*sealedName,
				New2B(*sealedPublic),
				TPM2BPrivate{Buffer: duplicate},
				TPM2BEncryptedSecret{Buffer: seed},
			)
			if err != nil {
				t.Fatalf("NewMigration() = %v", err)
			}
			loaded, err := migration.Load(thetpm)
			if err != nil {
				t.Fatalf("Migration.Load() = %v", err)
			}
			defer func() {
				if err := loaded.Flush(thetpm); err != nil {
					t.Errorf("LoadedObject.Flush() = %v", err)
				}
			}()

			if !bytes.Equal(loaded.Name.Buffer, sealedName.Buffer) {
				t.Errorf("loaded Name = %x, want %x", loaded.Name.Buffer, sealedName.Buffer)
			}
			expectedPublic := New2B(*sealedPublic)
			if !bytes.Equal(loaded.Public.Bytes(), expectedPublic.Bytes()) {
				t.Errorf("loaded Public = %x, want %x", loaded.Public.Bytes(), expectedPublic.Bytes())
			}
			unseal, err := Unseal{
				ItemHandle: NamedHandle{
					Handle: loaded.Handle,
					Name:   loaded.Name,
				},
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("Unseal() = %v", err)
			}
			if !bytes.Equal(unseal.OutData.Buffer, plaintext) {
				t.Errorf("Unseal() = %x, want %x", unseal.OutData.Buffer, plaintext)
			}
		})
	}
}

func TestMigrationRetryWithAnotherParent(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	firstParent, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary(first) = %v", err)
	}
	defer FlushContext{FlushHandle: firstParent.ObjectHandle}.Execute(thetpm)

	secondParent, err := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(RSASRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary(second) = %v", err)
	}
	defer FlushContext{FlushHandle: secondParent.ObjectHandle}.Execute(thetpm)

	plaintext := []byte("retry with a different parent")
	sealedPublic, sealedPrivate := makeSealedBlob(t, TPMAlgSHA256, make([]byte, 32), plaintext)
	sealedName, err := ObjectName(sealedPublic)
	if err != nil {
		t.Fatalf("ObjectName() = %v", err)
	}

	newDuplicate := func(parent *CreatePrimaryResponse) ([]byte, []byte) {
		t.Helper()
		parentPublic, err := parent.OutPublic.Contents()
		if err != nil {
			t.Fatalf("parent.OutPublic.Contents() = %v", err)
		}
		key, err := ImportEncapsulationKey(parentPublic)
		if err != nil {
			t.Fatalf("ImportEncapsulationKey() = %v", err)
		}
		duplicate, seed, err := CreateDuplicate(rand.Reader, key, sealedName.Buffer, sealedPrivate)
		if err != nil {
			t.Fatalf("CreateDuplicate() = %v", err)
		}
		return duplicate, seed
	}

	firstDuplicate, firstSeed := newDuplicate(firstParent)
	secondDuplicate, secondSeed := newDuplicate(secondParent)
	brokenSeed := append([]byte(nil), firstSeed...)
	brokenSeed[0] ^= 0xff

	broken, err := NewMigration(
		AuthHandle{Handle: firstParent.ObjectHandle, Name: firstParent.Name, Auth: PasswordAuth(nil)},
		*sealedName,
		New2B(*sealedPublic),
		TPM2BPrivate{Buffer: firstDuplicate},
		TPM2BEncryptedSecret{Buffer: brokenSeed},
	)
	if err != nil {
		t.Fatalf("NewMigration(broken) = %v", err)
	}
	valid, err := NewMigration(
		AuthHandle{Handle: secondParent.ObjectHandle, Name: secondParent.Name, Auth: PasswordAuth(nil)},
		*sealedName,
		New2B(*sealedPublic),
		TPM2BPrivate{Buffer: secondDuplicate},
		TPM2BEncryptedSecret{Buffer: secondSeed},
	)
	if err != nil {
		t.Fatalf("NewMigration(valid) = %v", err)
	}

	loaded, err := LoadFirstMigration(thetpm, []*Migration{broken, valid})
	if err != nil {
		t.Fatalf("LoadFirstMigration() = %v", err)
	}
	defer func() {
		if err := loaded.Flush(thetpm); err != nil {
			t.Errorf("LoadedObject.Flush() = %v", err)
		}
	}()
	if !bytes.Equal(loaded.Name.Buffer, sealedName.Buffer) {
		t.Errorf("loaded Name = %x, want %x", loaded.Name.Buffer, sealedName.Buffer)
	}
	expectedPublic := New2B(*sealedPublic)
	if !bytes.Equal(loaded.Public.Bytes(), expectedPublic.Bytes()) {
		t.Errorf("loaded Public = %x, want %x", loaded.Public.Bytes(), expectedPublic.Bytes())
	}
	unseal, err := Unseal{
		ItemHandle: NamedHandle{Handle: loaded.Handle, Name: loaded.Name},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Unseal() = %v", err)
	}
	if !bytes.Equal(unseal.OutData.Buffer, plaintext) {
		t.Errorf("Unseal() = %x, want %x", unseal.OutData.Buffer, plaintext)
	}

	// The duplicate and seed from the second parent must not load under the
	// first parent, even if the caller swaps only the outer parent.
	swapped := *valid
	swapped.OuterParent = AuthHandle{
		Handle: firstParent.ObjectHandle,
		Name:   firstParent.Name,
		Auth:   PasswordAuth(nil),
	}
	if _, err := swapped.Load(thetpm); err == nil {
		t.Fatal("Migration.Load() with a swapped outer parent = nil, want error")
	}
}

func TestMigrationNullParent(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	parent, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary() = %v", err)
	}
	defer FlushContext{FlushHandle: parent.ObjectHandle}.Execute(thetpm)

	plaintext := []byte("null hierarchy migration")
	created, err := CreateLoaded{
		ParentHandle: NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{Buffer: plaintext}),
			},
		},
		InPublic: New2BTemplate(&TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:     false,
				FixedParent:  false,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreateLoaded() = %v", err)
	}
	defer FlushContext{FlushHandle: created.ObjectHandle}.Execute(thetpm)

	duplicate, err := Duplicate{
		ObjectHandle: AuthHandle{
			Handle: created.ObjectHandle,
			Name:   created.Name,
			Auth:   PasswordAuth(nil),
		},
		NewParentHandle: TPMRHNull,
		Symmetric:       TPMTSymDef{Algorithm: TPMAlgNull},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Duplicate() = %v", err)
	}
	if len(duplicate.OutSymSeed.Buffer) != 0 {
		t.Errorf("Duplicate() seed for null parent = %x, want empty", duplicate.OutSymSeed.Buffer)
	}

	migration, err := NewMigration(
		TPMRHNull,
		created.Name,
		created.OutPublic,
		duplicate.Duplicate,
		duplicate.OutSymSeed,
	)
	if err != nil {
		t.Fatalf("NewMigration() = %v", err)
	}
	loaded, err := migration.Load(thetpm)
	if err != nil {
		t.Fatalf("Migration.Load() = %v", err)
	}
	defer func() {
		if err := loaded.Flush(thetpm); err != nil {
			t.Errorf("LoadedObject.Flush() = %v", err)
		}
	}()

	unseal, err := Unseal{
		ItemHandle: NamedHandle{Handle: loaded.Handle, Name: loaded.Name},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Unseal() = %v", err)
	}
	if !bytes.Equal(unseal.OutData.Buffer, plaintext) {
		t.Errorf("Unseal() = %x, want %x", unseal.OutData.Buffer, plaintext)
	}
}
