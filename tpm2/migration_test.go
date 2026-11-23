package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

type migrationTestStep struct {
	code    TPMRC
	handles []uint32
	params  []byte
}

type migrationTestTPM struct {
	steps         map[TPMCC][]migrationTestStep
	calls         []TPMCC
	importParents []TPMHandle
	loadParents   []TPMHandle
	flushed       []TPMHandle
}

func newMigrationTestTPM() *migrationTestTPM {
	return &migrationTestTPM{steps: make(map[TPMCC][]migrationTestStep)}
}

func (f *migrationTestTPM) add(cc TPMCC, steps ...migrationTestStep) {
	f.steps[cc] = append(f.steps[cc], steps...)
}

func (f *migrationTestTPM) count(cc TPMCC) int {
	count := 0
	for _, called := range f.calls {
		if called == cc {
			count++
		}
	}
	return count
}

func (f *migrationTestTPM) Send(input []byte) ([]byte, error) {
	if len(input) < 10 {
		return nil, fmt.Errorf("short TPM command: %d bytes", len(input))
	}
	cc := TPMCC(binary.BigEndian.Uint32(input[6:10]))
	f.calls = append(f.calls, cc)

	if cc == TPMCCFlushContext {
		if len(input) >= 14 {
			f.flushed = append(f.flushed, TPMHandle(binary.BigEndian.Uint32(input[10:14])))
		}
		return migrationTestResponse(TPMRCSuccess, nil, nil, false), nil
	}
	if len(input) >= 14 {
		switch cc {
		case TPMCCImport:
			f.importParents = append(f.importParents, TPMHandle(binary.BigEndian.Uint32(input[10:14])))
		case TPMCCLoad:
			f.loadParents = append(f.loadParents, TPMHandle(binary.BigEndian.Uint32(input[10:14])))
		}
	}

	queue := f.steps[cc]
	if len(queue) == 0 {
		return nil, fmt.Errorf("unexpected TPM command %v", cc)
	}
	step := queue[0]
	f.steps[cc] = queue[1:]
	if step.code != TPMRCSuccess {
		return migrationTestResponse(step.code, nil, nil, false), nil
	}
	withSessions := binary.BigEndian.Uint16(input[0:2]) == uint16(TPMSTSessions)
	return migrationTestResponse(TPMRCSuccess, step.handles, step.params, withSessions), nil
}

func migrationTestResponse(code TPMRC, handles []uint32, params []byte, withSessions bool) []byte {
	tag := TPMSTNoSessions
	parameterArea := params
	var sessions []byte
	if withSessions {
		tag = TPMSTSessions
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(params)))
		parameterArea = append(length, params...)
		sessions = Marshal(TPMSAuthResponse{
			Nonce:         TPM2BNonce{},
			Attributes:    TPMASession{ContinueSession: true},
			Authorization: TPM2BData{},
		})
	}
	header := TPMRspHeader{
		Tag:          tag,
		Length:       uint32(10 + 4*len(handles) + len(parameterArea) + len(sessions)),
		ResponseCode: code,
	}
	response := Marshal(header)
	for _, handle := range handles {
		encoded := make([]byte, 4)
		binary.BigEndian.PutUint32(encoded, handle)
		response = append(response, encoded...)
	}
	response = append(response, parameterArea...)
	response = append(response, sessions...)
	return response
}

func migrationTestPublic(t *testing.T, template TPMTPublic) (TPM2BPublic, TPM2BName) {
	t.Helper()
	name, err := ObjectName(&template)
	if err != nil {
		t.Fatalf("ObjectName() = %v", err)
	}
	return New2B(template), *name
}

func migrationTestParent(handle TPMHandle, name string) NamedHandle {
	return NamedHandle{
		Handle: handle,
		Name:   TPM2BName{Buffer: []byte(name)},
	}
}

func migrationTestReadPublic(t *testing.T, public TPM2BPublic, name TPM2BName) migrationTestStep {
	t.Helper()
	params := append(Marshal(public), Marshal(name)...)
	params = append(params, Marshal(TPM2BName{})...)
	return migrationTestStep{params: params}
}

func TestNewMigrationBindsSourceName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template TPMTPublic
	}{
		{name: "ECC", template: ECCSRKTemplate},
		{name: "RSA", template: RSASRKTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, sourceName := migrationTestPublic(t, tc.template)
			parent := migrationTestParent(0x80000001, "outer-parent")

			migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
			if err != nil {
				t.Fatalf("NewMigration() = %v", err)
			}
			if !bytes.Equal(migration.SourceName.Buffer, sourceName.Buffer) {
				t.Errorf("SourceName = %x, want %x", migration.SourceName.Buffer, sourceName.Buffer)
			}

			// An empty source name is derived from the public area.
			derived, err := NewMigration(parent, TPM2BName{}, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
			if err != nil {
				t.Fatalf("NewMigration() with empty source name = %v", err)
			}
			if !bytes.Equal(derived.SourceName.Buffer, sourceName.Buffer) {
				t.Errorf("derived SourceName = %x, want %x", derived.SourceName.Buffer, sourceName.Buffer)
			}

			wrongName := TPM2BName{Buffer: append([]byte(nil), sourceName.Buffer...)}
			wrongName.Buffer[len(wrongName.Buffer)-1] ^= 0xff
			if _, err := NewMigration(parent, wrongName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}}); !errors.Is(err, ErrMigrationSourceName) {
				t.Errorf("NewMigration() with mismatched source name = %v, want %v", err, ErrMigrationSourceName)
			}
		})
	}
}

func TestNewMigrationValidatesParentAndDuplicate(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	parent := migrationTestParent(0x80000001, "outer-parent")

	if _, err := NewMigration(parent, sourceName, public, TPM2BPrivate{}, TPM2BEncryptedSecret{Buffer: []byte{0x02}}); !errors.Is(err, ErrMigrationDuplicate) {
		t.Errorf("NewMigration() without duplicate = %v, want %v", err, ErrMigrationDuplicate)
	}
	if _, err := NewMigration(nil, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}}); !errors.Is(err, ErrMigrationParent) {
		t.Errorf("NewMigration() without parent = %v, want %v", err, ErrMigrationParent)
	}
	// An empty seed is valid for a legacy cleartext import blob, even under a
	// non-null parent. The TPM remains the authority on whether the duplicate
	// can be imported.
	if _, err := NewMigration(TPMHandle(TPMRHOwner), sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{}); err != nil {
		t.Errorf("NewMigration() with cleartext import blob = %v, want nil", err)
	}
}

func TestMigrationNullHierarchyAllowsEmptySeed(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	migration, err := NewMigration(TPMRHNull, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{})
	if err != nil {
		t.Fatalf("NewMigration() for null hierarchy = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport, migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x10, 0x20}})})
	fake.add(TPMCCLoad, migrationTestStep{
		handles: []uint32{0x80000002},
		params:  Marshal(migration.SourceName),
	})
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, migration.SourceName))

	loaded, err := migration.Load(fake)
	if err != nil {
		t.Fatalf("Migration.Load() for null hierarchy = %v", err)
	}
	if loaded.Handle != 0x80000002 {
		t.Errorf("loaded handle = %#x, want %#x", loaded.Handle, 0x80000002)
	}
	if len(fake.importParents) != 1 || fake.importParents[0] != TPMRHNull {
		t.Errorf("import parent = %v, want %v", fake.importParents, TPMRHNull)
	}
}

func TestMigrationAcceptsOpaqueImportBlob(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	parent := migrationTestParent(0x80000001, "outer-parent")
	legacyBlob := []byte{0x00, 0x00, 0x01, 0x7f, 0xff}
	legacySeed := []byte{0xaa, 0xbb, 0xcc}

	migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: legacyBlob}, TPM2BEncryptedSecret{Buffer: legacySeed})
	if err != nil {
		t.Fatalf("NewMigration() with legacy blob = %v", err)
	}
	if !bytes.Equal(migration.Duplicate.Buffer, legacyBlob) {
		t.Errorf("Duplicate = %x, want %x", migration.Duplicate.Buffer, legacyBlob)
	}
	if !bytes.Equal(migration.InSymSeed.Buffer, legacySeed) {
		t.Errorf("InSymSeed = %x, want %x", migration.InSymSeed.Buffer, legacySeed)
	}

	// The migration must be a snapshot, not an alias of caller-owned buffers.
	legacyBlob[0] ^= 0xff
	if bytes.Equal(migration.Duplicate.Buffer, legacyBlob) {
		t.Error("Migration.Duplicate aliases the caller's blob")
	}
}

func TestMigrationAcceptsCleartextImportBlob(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	parent := migrationTestParent(0x80000001, "outer-parent")
	private := []byte{0x44, 0x55}
	migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{})
	if err != nil {
		t.Fatalf("NewMigration() with cleartext blob = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport, migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: private})})
	fake.add(TPMCCLoad, migrationTestStep{
		handles: []uint32{0x80000008},
		params:  Marshal(sourceName),
	})
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, sourceName))

	loaded, err := migration.Load(fake)
	if err != nil {
		t.Fatalf("Migration.Load() with cleartext blob = %v", err)
	}
	if !bytes.Equal(loaded.Private.Buffer, private) {
		t.Errorf("Private = %x, want %x", loaded.Private.Buffer, private)
	}
}

func TestMigrationLoadBindsPublicPrivateAndName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template TPMTPublic
	}{
		{name: "ECC", template: ECCSRKTemplate},
		{name: "RSA", template: RSASRKTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, sourceName := migrationTestPublic(t, tc.template)
			parent := migrationTestParent(0x80000001, "outer-parent")
			private := []byte{0x10, 0x20, 0x30}
			migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
			if err != nil {
				t.Fatalf("NewMigration() = %v", err)
			}

			fake := newMigrationTestTPM()
			fake.add(TPMCCImport, migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: private})})
			fake.add(TPMCCLoad, migrationTestStep{
				handles: []uint32{0x80000002},
				params:  Marshal(sourceName),
			})
			fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, sourceName))

			loaded, err := migration.Load(fake)
			if err != nil {
				t.Fatalf("Migration.Load() = %v", err)
			}
			if loaded.Handle != 0x80000002 {
				t.Errorf("Handle = %#x, want %#x", loaded.Handle, 0x80000002)
			}
			if !bytes.Equal(loaded.Name.Buffer, sourceName.Buffer) {
				t.Errorf("Name = %x, want %x", loaded.Name.Buffer, sourceName.Buffer)
			}
			if !bytes.Equal(loaded.Public.Bytes(), public.Bytes()) {
				t.Errorf("Public = %x, want %x", loaded.Public.Bytes(), public.Bytes())
			}
			if !bytes.Equal(loaded.Private.Buffer, private) {
				t.Errorf("Private = %x, want %x", loaded.Private.Buffer, private)
			}
			if fake.count(TPMCCImport) != 1 || fake.count(TPMCCLoad) != 1 || fake.count(TPMCCReadPublic) != 1 {
				t.Errorf("commands = %v, want one Import, one Load, one ReadPublic", fake.calls)
			}
		})
	}
}

func TestMigrationLoadRejectsAnotherObject(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	otherPublic, otherName := migrationTestPublic(t, RSASRKTemplate)
	parent := migrationTestParent(0x80000001, "outer-parent")
	migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
	if err != nil {
		t.Fatalf("NewMigration() = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport, migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x10}})})
	fake.add(TPMCCLoad, migrationTestStep{
		handles: []uint32{0x80000003},
		params:  Marshal(otherName),
	})
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, otherPublic, otherName))

	if _, err := migration.Load(fake); !errors.Is(err, ErrObjectNameMismatch) {
		t.Fatalf("Migration.Load() with another object's Name = %v, want %v", err, ErrObjectNameMismatch)
	}
	if len(fake.flushed) != 1 || fake.flushed[0] != 0x80000003 {
		t.Errorf("flushed handles = %v, want [%#x]", fake.flushed, 0x80000003)
	}
	if fake.count(TPMCCReadPublic) != 0 {
		t.Errorf("ReadPublic called after Name mismatch: %v", fake.calls)
	}
}

func TestLoadFirstMigrationRetriesWithAnotherParent(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	firstParent := migrationTestParent(0x80000001, "first-parent")
	secondParent := migrationTestParent(0x80000002, "second-parent")
	first, err := NewMigration(firstParent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
	if err != nil {
		t.Fatalf("NewMigration(first) = %v", err)
	}
	second, err := NewMigration(secondParent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x03}}, TPM2BEncryptedSecret{Buffer: []byte{0x04}})
	if err != nil {
		t.Fatalf("NewMigration(second) = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport,
		migrationTestStep{code: TPMRCValue},
		migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x20}})},
	)
	fake.add(TPMCCLoad, migrationTestStep{
		handles: []uint32{0x80000004},
		params:  Marshal(sourceName),
	})
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, sourceName))

	loaded, err := LoadFirstMigration(fake, []*Migration{first, second})
	if err != nil {
		t.Fatalf("LoadFirstMigration() = %v", err)
	}
	if loaded.Handle != 0x80000004 {
		t.Errorf("Handle = %#x, want %#x", loaded.Handle, 0x80000004)
	}
	if !bytes.Equal(loaded.Private.Buffer, []byte{0x20}) {
		t.Errorf("Private = %x, want 20", loaded.Private.Buffer)
	}
	if len(fake.importParents) != 2 ||
		fake.importParents[0] != firstParent.Handle ||
		fake.importParents[1] != secondParent.Handle {
		t.Errorf("import parents = %v, want [%#x %#x]", fake.importParents, firstParent.Handle, secondParent.Handle)
	}
	if len(fake.loadParents) != 1 || fake.loadParents[0] != secondParent.Handle {
		t.Errorf("load parents = %v, want [%#x]", fake.loadParents, secondParent.Handle)
	}
	if len(fake.flushed) != 0 {
		t.Errorf("flushed handles = %v, want none", fake.flushed)
	}
}

func TestLoadFirstMigrationFlushesMismatchedHandle(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	_, otherName := migrationTestPublic(t, RSASRKTemplate)
	firstParent := migrationTestParent(0x80000001, "first-parent")
	secondParent := migrationTestParent(0x80000002, "second-parent")
	first, err := NewMigration(firstParent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
	if err != nil {
		t.Fatalf("NewMigration(first) = %v", err)
	}
	second, err := NewMigration(secondParent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x03}}, TPM2BEncryptedSecret{Buffer: []byte{0x04}})
	if err != nil {
		t.Fatalf("NewMigration(second) = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport,
		migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x10}})},
		migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x20}})},
	)
	fake.add(TPMCCLoad,
		migrationTestStep{handles: []uint32{0x80000005}, params: Marshal(otherName)},
		migrationTestStep{handles: []uint32{0x80000006}, params: Marshal(sourceName)},
	)
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, sourceName))

	loaded, err := LoadFirstMigration(fake, []*Migration{first, second})
	if err != nil {
		t.Fatalf("LoadFirstMigration() = %v", err)
	}
	if loaded.Handle != 0x80000006 {
		t.Errorf("Handle = %#x, want %#x", loaded.Handle, 0x80000006)
	}
	if len(fake.flushed) != 1 || fake.flushed[0] != 0x80000005 {
		t.Errorf("flushed handles = %v, want [%#x]", fake.flushed, 0x80000005)
	}
	if !bytes.Equal(loaded.Private.Buffer, []byte{0x20}) {
		t.Errorf("Private = %x, want 20", loaded.Private.Buffer)
	}
}

func TestImportedObjectLoadRetriesWithSameTransaction(t *testing.T) {
	public, sourceName := migrationTestPublic(t, ECCSRKTemplate)
	parent := migrationTestParent(0x80000001, "outer-parent")
	migration, err := NewMigration(parent, sourceName, public, TPM2BPrivate{Buffer: []byte{0x01}}, TPM2BEncryptedSecret{Buffer: []byte{0x02}})
	if err != nil {
		t.Fatalf("NewMigration() = %v", err)
	}

	fake := newMigrationTestTPM()
	fake.add(TPMCCImport, migrationTestStep{params: Marshal(TPM2BPrivate{Buffer: []byte{0x10}})})
	fake.add(TPMCCLoad,
		migrationTestStep{code: TPMRCValue},
		migrationTestStep{handles: []uint32{0x80000007}, params: Marshal(sourceName)},
	)
	fake.add(TPMCCReadPublic, migrationTestReadPublic(t, public, sourceName))

	imported, err := migration.Import(fake)
	if err != nil {
		t.Fatalf("Migration.Import() = %v", err)
	}
	if _, err := imported.Load(fake); err == nil {
		t.Fatal("ImportedObject.Load() = nil, want TPM error")
	}
	loaded, err := imported.Load(fake)
	if err != nil {
		t.Fatalf("ImportedObject.Load() retry = %v", err)
	}
	if loaded.Handle != 0x80000007 {
		t.Errorf("Handle = %#x, want %#x", loaded.Handle, 0x80000007)
	}
	if len(fake.loadParents) != 2 ||
		fake.loadParents[0] != parent.Handle ||
		fake.loadParents[1] != parent.Handle {
		t.Errorf("load parents = %v, want [%#x %#x]", fake.loadParents, parent.Handle, parent.Handle)
	}
	if _, err := imported.Load(fake); !errors.Is(err, ErrMigrationAlreadyLoaded) {
		t.Errorf("second successful Load() = %v, want %v", err, ErrMigrationAlreadyLoaded)
	}
}

func TestLoadFirstMigrationRequiresCandidates(t *testing.T) {
	if _, err := LoadFirstMigration(newMigrationTestTPM(), nil); !errors.Is(err, ErrNoMigrations) {
		t.Errorf("LoadFirstMigration() = %v, want %v", err, ErrNoMigrations)
	}
}
