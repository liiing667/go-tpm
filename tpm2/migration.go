package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

var (
	// ErrMigrationParent indicates that a migration has no usable outer parent.
	ErrMigrationParent = errors.New("tpm2: migration has no outer parent")
	// ErrMigrationSourceName indicates that the source Name does not identify
	// the migration's public area.
	ErrMigrationSourceName = errors.New("tpm2: migration source name does not match object public area")
	// ErrMigrationDuplicate indicates that a migration has no duplicate blob.
	ErrMigrationDuplicate = errors.New("tpm2: migration duplicate is empty")
	// ErrObjectNameMismatch indicates that a TPM object's Name does not match
	// its public area.
	ErrObjectNameMismatch = errors.New("tpm2: object Name does not match its public area")
	// ErrMigrationObjectMismatch indicates that a loaded object is not the
	// object described by its migration.
	ErrMigrationObjectMismatch = errors.New("tpm2: loaded object does not match migration")
	// ErrMigrationAlreadyLoaded indicates that an imported object has already
	// been loaded once.
	ErrMigrationAlreadyLoaded = errors.New("tpm2: imported object was already loaded")
	// ErrNoMigrations indicates that LoadFirstMigration was called with no
	// migration candidates.
	ErrNoMigrations = errors.New("tpm2: no migrations to load")
)

// MigrationParent is a TPM handle used as a migration's outer parent. It may
// be a TPMHandle, NamedHandle, or AuthHandle.
type MigrationParent interface {
	HandleValue() uint32
	KnownName() *TPM2BName
}

// Migration binds every piece of state needed to move one object to an outer
// parent: the source object's Name, the duplicate blob, the outer parent, and
// the import seed. Import and Load always use the state from the same
// Migration, so retrying an import or changing the outer parent cannot
// accidentally combine a name from one object with public/private data from
// another.
//
// A Migration is a snapshot. Construct it with NewMigration or
// NewMigrationFromDuplicate so its byte slices do not alias caller-owned
// buffers.
type Migration struct {
	// OuterParent is the parent under which the object is imported and loaded.
	OuterParent MigrationParent
	// SourceName is the TPM Name of ObjectPublic. If it is empty, the Name is
	// derived from ObjectPublic.
	SourceName TPM2BName
	// ObjectPublic is the public area of the object being migrated.
	ObjectPublic TPM2BPublic
	// Duplicate is the private area produced for OuterParent by
	// TPM2_Duplicate or CreateDuplicate.
	Duplicate TPM2BPrivate
	// InSymSeed is the seed produced for OuterParent. It may be empty for a
	// null outer parent or for a legacy cleartext import blob.
	InSymSeed TPM2BEncryptedSecret
	// EncryptionKey is the optional inner-wrapper key used by Import.
	EncryptionKey TPM2BData
	// Symmetric describes the optional inner wrapper used by Import.
	Symmetric TPMTSymDef
}

// NewMigration validates and snapshots a migration. Empty sourceName is
// allowed for callers that only have a public area; it is derived from
// objectPublic. A non-empty sourceName must be the Name of objectPublic.
func NewMigration(outerParent MigrationParent, sourceName TPM2BName, objectPublic TPM2BPublic, duplicate TPM2BPrivate, inSymSeed TPM2BEncryptedSecret) (*Migration, error) {
	migration := &Migration{
		OuterParent:  outerParent,
		SourceName:   TPM2BName{Buffer: cloneMigrationBytes(sourceName.Buffer)},
		ObjectPublic: BytesAs2B[TPMTPublic](cloneMigrationBytes(objectPublic.Bytes())),
		Duplicate:    TPM2BPrivate{Buffer: cloneMigrationBytes(duplicate.Buffer)},
		InSymSeed:    TPM2BEncryptedSecret{Buffer: cloneMigrationBytes(inSymSeed.Buffer)},
	}
	name, err := migration.validate()
	if err != nil {
		return nil, err
	}
	if len(migration.SourceName.Buffer) == 0 {
		migration.SourceName = name
	}
	return migration, nil
}

// NewMigrationFromDuplicate creates a Migration from the output of a
// TPM2_Duplicate command. symmetric must describe the inner wrapper that was
// requested from TPM2_Duplicate; use TPMTSymDef{Algorithm: TPMAlgNull} when
// no inner wrapper was used.
func NewMigrationFromDuplicate(outerParent MigrationParent, sourceName TPM2BName, objectPublic TPM2BPublic, duplicate *DuplicateResponse, symmetric TPMTSymDef) (*Migration, error) {
	if duplicate == nil {
		return nil, errors.New("tpm2: duplicate response is nil")
	}
	migration, err := NewMigration(outerParent, sourceName, objectPublic, duplicate.Duplicate, duplicate.OutSymSeed)
	if err != nil {
		return nil, err
	}
	migration.EncryptionKey = TPM2BData{Buffer: cloneMigrationBytes(duplicate.EncryptionKeyOut.Buffer)}
	migration.Symmetric = symmetric
	return migration, nil
}

// Import runs TPM2_Import and returns an object that can only be loaded under
// this migration's outer parent and with this migration's public area and
// source Name.
func (m Migration) Import(t transport.TPM, s ...Session) (*ImportedObject, error) {
	migration := m.clone()
	name, err := migration.validate()
	if err != nil {
		return nil, err
	}
	rsp, err := Import{
		ParentHandle:  migration.OuterParent,
		EncryptionKey: migration.EncryptionKey,
		ObjectPublic:  migration.ObjectPublic,
		Duplicate:     migration.Duplicate,
		InSymSeed:     migration.InSymSeed,
		Symmetric:     migration.Symmetric,
	}.Execute(t, s...)
	if err != nil {
		return nil, fmt.Errorf("importing migrated object: %w", err)
	}
	if len(rsp.OutPrivate.Buffer) == 0 {
		return nil, errors.New("importing migrated object: TPM returned an empty private area")
	}
	return &ImportedObject{
		migration: migration,
		name:      name,
		private:   TPM2BPrivate{Buffer: cloneMigrationBytes(rsp.OutPrivate.Buffer)},
	}, nil
}

// Load imports and then loads the object as one transaction. If any step
// fails, no loaded handle is returned; a handle created by a failed
// verification is flushed before the error is returned.
func (m Migration) Load(t transport.TPM, s ...Session) (*LoadedObject, error) {
	imported, err := m.Import(t, s...)
	if err != nil {
		return nil, err
	}
	return imported.Load(t, s...)
}

// ImportedObject is the result of a successful TPM2_Import that remains bound
// to its Migration. Load can be retried after a load failure, but it always
// uses the same outer parent, public area, source Name, and private area.
type ImportedObject struct {
	mu        sync.Mutex
	migration Migration
	name      TPM2BName
	private   TPM2BPrivate
	loaded    bool
}

// Name returns the source Name bound to this import.
func (i *ImportedObject) Name() TPM2BName {
	if i == nil {
		return TPM2BName{}
	}
	return TPM2BName{Buffer: cloneMigrationBytes(i.name.Buffer)}
}

// Public returns the public area bound to this import.
func (i *ImportedObject) Public() TPM2BPublic {
	if i == nil {
		return TPM2BPublic{}
	}
	return BytesAs2B[TPMTPublic](cloneMigrationBytes(i.migration.ObjectPublic.Bytes()))
}

// Private returns the private area produced by TPM2_Import.
func (i *ImportedObject) Private() TPM2BPrivate {
	if i == nil {
		return TPM2BPrivate{}
	}
	return TPM2BPrivate{Buffer: cloneMigrationBytes(i.private.Buffer)}
}

// Load loads the imported object and verifies that the TPM returned the
// object described by the migration. A successfully loaded object can be
// returned at most once. If the verification fails, the loaded handle is
// flushed so that the caller cannot accidentally use another object.
func (i *ImportedObject) Load(t transport.TPM, s ...Session) (*LoadedObject, error) {
	if i == nil {
		return nil, errors.New("tpm2: imported object is nil")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.loaded {
		return nil, ErrMigrationAlreadyLoaded
	}

	migration := i.migration.clone()
	name := TPM2BName{Buffer: cloneMigrationBytes(i.name.Buffer)}
	loadRsp, err := Load{
		ParentHandle: migration.OuterParent,
		InPrivate:    TPM2BPrivate{Buffer: cloneMigrationBytes(i.private.Buffer)},
		InPublic:     migration.ObjectPublic,
	}.Execute(t, s...)
	if err != nil {
		if errors.Is(err, ErrObjectNameMismatch) {
			return nil, fmt.Errorf("%w: %w", ErrMigrationObjectMismatch, err)
		}
		return nil, fmt.Errorf("loading migrated object: %w", err)
	}
	if !bytes.Equal(loadRsp.Name.Buffer, name.Buffer) {
		return abortLoad(t, loadRsp.ObjectHandle, fmt.Errorf(
			"%w: loaded name %x, source name %x",
			ErrMigrationObjectMismatch, loadRsp.Name.Buffer, name.Buffer))
	}

	readRsp, err := ReadPublic{ObjectHandle: loadRsp.ObjectHandle}.Execute(t)
	if err != nil {
		return abortLoad(t, loadRsp.ObjectHandle, fmt.Errorf("reading back migrated object: %w", err))
	}
	readName, err := migrationPublicName(readRsp.OutPublic)
	if err != nil {
		return abortLoad(t, loadRsp.ObjectHandle, fmt.Errorf("reading back migrated object: %w", err))
	}
	if !bytes.Equal(readRsp.Name.Buffer, name.Buffer) || !bytes.Equal(readName.Buffer, name.Buffer) {
		return abortLoad(t, loadRsp.ObjectHandle, fmt.Errorf(
			"%w: read-back public area or Name does not match migration",
			ErrMigrationObjectMismatch))
	}

	i.loaded = true
	return &LoadedObject{
		Handle:      loadRsp.ObjectHandle,
		Name:        TPM2BName{Buffer: cloneMigrationBytes(name.Buffer)},
		Public:      BytesAs2B[TPMTPublic](cloneMigrationBytes(readRsp.OutPublic.Bytes())),
		Private:     TPM2BPrivate{Buffer: cloneMigrationBytes(i.private.Buffer)},
		OuterParent: migration.OuterParent,
	}, nil
}

// LoadedObject is a loaded object whose handle, Name, public area, private
// area, and outer parent all come from one Migration transaction.
type LoadedObject struct {
	Handle      TPMHandle
	Name        TPM2BName
	Public      TPM2BPublic
	Private     TPM2BPrivate
	OuterParent MigrationParent
}

// Flush flushes the loaded handle. It is safe to call on a nil LoadedObject
// or after the handle has already been flushed.
func (o *LoadedObject) Flush(t transport.TPM, s ...Session) error {
	if o == nil || o.Handle == 0 {
		return nil
	}
	if err := flushContext(t, o.Handle); err != nil {
		return fmt.Errorf("flushing loaded object: %w", err)
	}
	o.Handle = 0
	return nil
}

// LoadFirstMigration tries each migration in order. A failed attempt is
// discarded in full before the next candidate is tried: Import is performed
// again with the candidate's own duplicate blob, seed, and outer parent, and
// any handle from a failed verification is flushed. It returns only a
// LoadedObject that belongs to exactly one successful migration.
func LoadFirstMigration(t transport.TPM, migrations []*Migration, s ...Session) (*LoadedObject, error) {
	if len(migrations) == 0 {
		return nil, ErrNoMigrations
	}
	var errs []error
	for index, migration := range migrations {
		if migration == nil {
			errs = append(errs, fmt.Errorf("migration %d: %w", index, ErrMigrationParent))
			continue
		}
		loaded, err := migration.Load(t, s...)
		if err == nil {
			return loaded, nil
		}
		parent, _ := migrationHandle(migration.OuterParent)
		errs = append(errs, fmt.Errorf("migration %d (parent %#x): %w", index, parent, err))
	}
	return nil, fmt.Errorf("all migrations failed: %w", errors.Join(errs...))
}

func (m Migration) clone() Migration {
	return Migration{
		OuterParent:   m.OuterParent,
		SourceName:    TPM2BName{Buffer: cloneMigrationBytes(m.SourceName.Buffer)},
		ObjectPublic:  BytesAs2B[TPMTPublic](cloneMigrationBytes(m.ObjectPublic.Bytes())),
		Duplicate:     TPM2BPrivate{Buffer: cloneMigrationBytes(m.Duplicate.Buffer)},
		InSymSeed:     TPM2BEncryptedSecret{Buffer: cloneMigrationBytes(m.InSymSeed.Buffer)},
		EncryptionKey: TPM2BData{Buffer: cloneMigrationBytes(m.EncryptionKey.Buffer)},
		Symmetric:     m.Symmetric,
	}
}

func (m Migration) validate() (TPM2BName, error) {
	parent, err := migrationHandle(m.OuterParent)
	if err != nil {
		return TPM2BName{}, err
	}
	if len(m.Duplicate.Buffer) == 0 {
		return TPM2BName{}, ErrMigrationDuplicate
	}
	name, err := migrationPublicName(m.ObjectPublic)
	if err != nil {
		return TPM2BName{}, err
	}
	if len(m.SourceName.Buffer) != 0 && !bytes.Equal(m.SourceName.Buffer, name.Buffer) {
		return TPM2BName{}, fmt.Errorf(
			"%w: source %x, public area %x",
			ErrMigrationSourceName, m.SourceName.Buffer, name.Buffer)
	}
	if parentName := m.OuterParent.KnownName(); parentName == nil || len(parentName.Buffer) == 0 {
		return TPM2BName{}, fmt.Errorf("%w: parent %#x has no Name", ErrMigrationParent, parent)
	}
	return name, nil
}

// verifyLoadResponse checks the Name returned by TPM2_Load against the public
// area the caller asked to load. This keeps a mismatched response from
// handing the caller a handle to a different object.
func verifyLoadResponse(t transport.TPM, public TPM2BPublic, rsp *LoadResponse) error {
	if rsp == nil {
		return nil
	}
	contents, err := Unmarshal[TPMTPublic](public.Bytes())
	if err != nil {
		// Preserve the previous behavior for opaque public areas. The TPM is
		// still responsible for validating the marshalled public area.
		return nil
	}
	expected, err := ObjectName(contents)
	if err != nil {
		// Unsupported Name algorithms cannot be checked locally.
		return nil
	}
	if bytes.Equal(rsp.Name.Buffer, expected.Buffer) {
		return nil
	}
	mismatch := fmt.Errorf(
		"%w: loaded name %x, public area name %x",
		ErrObjectNameMismatch, rsp.Name.Buffer, expected.Buffer)
	if err := flushContext(t, rsp.ObjectHandle); err != nil {
		return fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, rsp.ObjectHandle, err)
	}
	return mismatch
}

func migrationPublicName(public TPM2BPublic) (TPM2BName, error) {
	contents, err := Unmarshal[TPMTPublic](public.Bytes())
	if err != nil {
		return TPM2BName{}, fmt.Errorf("parsing object public area: %w", err)
	}
	name, err := ObjectName(contents)
	if err != nil {
		return TPM2BName{}, fmt.Errorf("computing object Name: %w", err)
	}
	return *name, nil
}

func migrationHandle(h MigrationParent) (TPMHandle, error) {
	if h == nil {
		return 0, ErrMigrationParent
	}
	value := TPMHandle(h.HandleValue())
	if value == 0 || value == invalidHandleValue {
		return 0, fmt.Errorf("%w: invalid handle %#x", ErrMigrationParent, value)
	}
	return value, nil
}

func flushContext(t transport.TPM, h TPMHandle) error {
	_, err := FlushContext{FlushHandle: h}.Execute(t)
	return err
}

func abortLoad(t transport.TPM, h TPMHandle, cause error) (*LoadedObject, error) {
	if err := flushContext(t, h); err != nil {
		return nil, fmt.Errorf("%w (also failed to flush %#x: %v)", cause, h, err)
	}
	return nil, cause
}

func cloneMigrationBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
