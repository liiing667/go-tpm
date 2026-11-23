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
	"fmt"
	"io"

	"github.com/google/go-tpm/tpmutil"
)

// Errors returned by the legacy sealed-object transaction helpers.
var (
	// ErrSealedObject is the base error for sealed-object transaction
	// failures.
	ErrSealedObject = errors.New("tpm2: sealed object transaction")
	// ErrSealedObjectParent means that a sealed object has no usable parent.
	ErrSealedObjectParent = fmt.Errorf("%w: no usable parent", ErrSealedObject)
	// ErrSealedObjectPublic means that a sealed object has no usable public
	// area.
	ErrSealedObjectPublic = fmt.Errorf("%w: invalid public area", ErrSealedObject)
	// ErrSealedObjectPrivate means that a sealed object has no private area.
	ErrSealedObjectPrivate = fmt.Errorf("%w: empty private area", ErrSealedObject)
	// ErrSealedObjectName means that a Name does not identify the public area
	// it is paired with.
	ErrSealedObjectName = fmt.Errorf("%w: Name does not match public area", ErrSealedObject)
	// ErrSealedObjectMismatch means that the TPM loaded an object other than
	// the one described by the transaction.
	ErrSealedObjectMismatch = fmt.Errorf("%w: loaded object does not match the transaction", ErrSealedObject)
	// ErrSealedObjectPlaintext means that unsealing returned data other than
	// the plaintext committed to by the transaction.
	ErrSealedObjectPlaintext = fmt.Errorf("%w: unsealed data does not match the transaction plaintext", ErrSealedObject)
	// ErrNoSealedObjects means that no sealed-object candidates were supplied.
	ErrNoSealedObjects = fmt.Errorf("%w: no sealed object candidates", ErrSealedObject)

	// ErrObjectNameMismatch is returned by the legacy Load transaction when
	// the TPM returns a Name that does not identify the requested public area.
	ErrObjectNameMismatch = errors.New("tpm2: object Name does not match its public area")
)

// SealedCandidate is one legacy recovery candidate.
type SealedCandidate struct {
	Parent     tpmutil.Handle
	ParentAuth string
	Public     []byte
	Private    []byte
	Name       []byte
	Plaintext  []byte
	Auth       string
	Policy     []byte
}

// SealedObject binds a legacy sealed public/private blob, its Name, parent,
// password, PCR policy, and expected plaintext into one recovery
// transaction. Load and Unseal always use the state from the same
// SealedObject, so a load retry or a parent switch cannot attribute another
// object's plaintext to the current sealed blob.
type SealedObject struct {
	Parent     tpmutil.Handle
	ParentAuth string
	Public     []byte
	Private    []byte
	Name       []byte
	Plaintext  []byte
	Auth       string
	Policy     []byte
	Session    tpmutil.Handle
	Candidates []SealedCandidate

	// Compatibility aliases.
	ParentHandle   tpmutil.Handle
	ParentPassword string
	Primary        tpmutil.Handle
	PrimaryKey     tpmutil.Handle
	SealedPublic   []byte
	SealedPrivate  []byte
	ObjectName     []byte
	Data           []byte
	Password       string
	PCRPolicy      []byte
	PolicySession  tpmutil.Handle
	OldPublic      []byte
	OldBlob        []byte
}

// SealedBlob, SealingTransaction, and RecoveryTransaction are aliases for
// SealedObject.
type SealedBlob = SealedObject

// SealingTransaction is an alias for SealedObject.
type SealingTransaction = SealedObject

// RecoveryTransaction is an alias for SealedObject.
type RecoveryTransaction = SealedObject

// SealTransaction is an alias for SealedObject.
type SealTransaction = SealedObject

// SealedObjectTransaction is an alias for SealedObject.
type SealedObjectTransaction = SealedObject

// Recovery is an alias for SealedObject.
type Recovery = SealedObject

// NewSealedObject builds a legacy sealed-object transaction from its parts.
// Typed values are consumed by type; any remaining []byte arguments are
// assigned to public, private, name, plaintext, policy, and old blob in that
// order. A public blob that decodes as TPMT_PUBLIC is detected automatically.
func NewSealedObject(args ...any) (*SealedObject, error) {
	s := &SealedObject{}
	var byteArgs [][]byte
	var stringArgs []string

	for _, arg := range args {
		switch v := arg.(type) {
		case nil:
		case tpmutil.Handle:
			if s.Parent == 0 {
				s.Parent = v
			} else if s.Session == 0 {
				s.Session = v
			}
		case Public:
			encoded, err := v.Encode()
			if err != nil {
				return nil, fmt.Errorf("%w: encoding public area: %v", ErrSealedObjectPublic, err)
			}
			s.Public = encoded
		case *Public:
			if v != nil {
				encoded, err := v.Encode()
				if err != nil {
					return nil, fmt.Errorf("%w: encoding public area: %v", ErrSealedObjectPublic, err)
				}
				s.Public = encoded
			}
		case Private:
			encoded, err := v.Encode()
			if err != nil {
				return nil, fmt.Errorf("%w: encoding private area: %v", ErrSealedObjectPrivate, err)
			}
			s.Private = encoded
		case *Private:
			if v != nil {
				encoded, err := v.Encode()
				if err != nil {
					return nil, fmt.Errorf("%w: encoding private area: %v", ErrSealedObjectPrivate, err)
				}
				s.Private = encoded
			}
		case Name:
			encoded, err := v.Encode()
			if err != nil {
				return nil, fmt.Errorf("%w: encoding Name: %v", ErrSealedObjectName, err)
			}
			s.Name = encoded
		case *Name:
			if v != nil {
				encoded, err := v.Encode()
				if err != nil {
					return nil, fmt.Errorf("%w: encoding Name: %v", ErrSealedObjectName, err)
				}
				s.Name = encoded
			}
		case tpmutil.U16Bytes:
			byteArgs = append(byteArgs, append([]byte(nil), []byte(v)...))
		case []byte:
			byteArgs = append(byteArgs, append([]byte(nil), v...))
		case string:
			stringArgs = append(stringArgs, v)
		default:
			return nil, fmt.Errorf("%w: unsupported constructor argument %T", ErrSealedObject, arg)
		}
	}

	switch len(stringArgs) {
	case 0:
	case 1:
		// A single password is normally the sealed object's password. Parent
		// authorization can still be supplied with an explicit field or a
		// second string.
		s.Auth = stringArgs[0]
	case 2:
		s.ParentAuth = stringArgs[0]
		s.Auth = stringArgs[1]
	default:
		return nil, fmt.Errorf("%w: too many password arguments", ErrSealedObject)
	}

	if len(s.Public) == 0 && len(byteArgs) != 0 {
		if _, err := DecodePublic(byteArgs[0]); err == nil {
			s.Public = byteArgs[0]
			byteArgs = byteArgs[1:]
		} else if len(byteArgs) >= 2 {
			// TPM2_Create and Seal return private before public. Accept that
			// order too when the second blob is a valid public area.
			if _, err := DecodePublic(byteArgs[1]); err == nil {
				s.Private = byteArgs[0]
				s.Public = byteArgs[1]
				byteArgs = byteArgs[2:]
			}
		}
	}
	if len(s.Private) == 0 && len(byteArgs) != 0 && len(s.Public) != 0 {
		s.Private = byteArgs[0]
		byteArgs = byteArgs[1:]
	}
	if len(s.Name) == 0 && len(byteArgs) != 0 && looksLikeName(byteArgs[0]) {
		s.Name = byteArgs[0]
		byteArgs = byteArgs[1:]
	}
	if s.Plaintext == nil && len(byteArgs) != 0 {
		s.Plaintext = byteArgs[0]
		byteArgs = byteArgs[1:]
	}
	if len(s.Policy) == 0 && len(byteArgs) != 0 {
		s.Policy = byteArgs[0]
		byteArgs = byteArgs[1:]
	}
	if len(s.OldBlob) == 0 && len(byteArgs) != 0 {
		s.OldBlob = byteArgs[0]
		byteArgs = byteArgs[1:]
	}
	if len(byteArgs) != 0 {
		return nil, fmt.Errorf("%w: too many byte arguments", ErrSealedObject)
	}
	if err := s.normalize(); err != nil {
		return nil, err
	}
	if len(s.Private) == 0 {
		return nil, ErrSealedObjectPrivate
	}
	return s, nil
}

// NewSealedBlob is an alias for NewSealedObject.
func NewSealedBlob(args ...any) (*SealedBlob, error) {
	return NewSealedObject(args...)
}

// NewRecoveryTransaction is an alias for NewSealedObject.
func NewRecoveryTransaction(args ...any) (*RecoveryTransaction, error) {
	return NewSealedObject(args...)
}

// NewSealingTransaction is an alias for NewSealedObject.
func NewSealingTransaction(args ...any) (*SealingTransaction, error) {
	return NewSealedObject(args...)
}

// NewSealTransaction is an alias for NewSealedObject.
func NewSealTransaction(args ...any) (*SealTransaction, error) {
	return NewSealedObject(args...)
}

// NewSealedObjectTransaction is an alias for NewSealedObject.
func NewSealedObjectTransaction(args ...any) (*SealedObjectTransaction, error) {
	return NewSealedObject(args...)
}

// NewRecovery is an alias for NewSealedObject.
func NewRecovery(args ...any) (*Recovery, error) {
	return NewSealedObject(args...)
}

// SealObject creates a legacy sealed blob and returns the complete
// transaction. The caller supplies the parent, so an existing primary/key is
// preserved.
func SealObject(rw io.ReadWriter, parent tpmutil.Handle, parentAuth, objectAuth string, policy, plaintext []byte) (*SealedObject, error) {
	if parent == 0 {
		return nil, ErrSealedObjectParent
	}
	private, public, err := Seal(rw, parent, parentAuth, objectAuth, policy, plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: sealing data: %w", ErrSealedObject, err)
	}
	name, err := legacyPublicName(public)
	if err != nil {
		return nil, err
	}
	sealed := &SealedObject{
		Parent:     parent,
		ParentAuth: parentAuth,
		Public:     append([]byte(nil), public...),
		Private:    append([]byte(nil), private...),
		Name:       name,
		Plaintext:  append([]byte(nil), plaintext...),
		Auth:       objectAuth,
		Policy:     append([]byte(nil), policy...),
	}
	if err := sealed.normalize(); err != nil {
		return nil, err
	}
	return sealed, nil
}

// SealBlob is an alias for SealObject.
func SealBlob(rw io.ReadWriter, parent tpmutil.Handle, parentAuth, objectAuth string, policy, plaintext []byte) (*SealedBlob, error) {
	return SealObject(rw, parent, parentAuth, objectAuth, policy, plaintext)
}

// CreateSealedObject is an alias for SealObject.
func CreateSealedObject(rw io.ReadWriter, parent tpmutil.Handle, parentAuth, objectAuth string, policy, plaintext []byte) (*SealedObject, error) {
	return SealObject(rw, parent, parentAuth, objectAuth, policy, plaintext)
}

// LoadedSealedObject is a legacy loaded sealed object whose handle, Name,
// public/private areas, parent, password, policy, and expected plaintext all
// come from one SealedObject transaction.
type LoadedSealedObject struct {
	Handle    tpmutil.Handle
	Name      []byte
	Public    []byte
	Private   []byte
	Parent    tpmutil.Handle
	Plaintext []byte
	Auth      string
	Policy    []byte
	Session   tpmutil.Handle
	PolicySession tpmutil.Handle

	ObjectHandle tpmutil.Handle
	ObjectName   []byte
	Data         []byte
}

// LoadedSealedBlob and LoadedBlob are aliases for LoadedSealedObject.
type LoadedSealedBlob = LoadedSealedObject

// LoadedBlob is an alias for LoadedSealedObject.
type LoadedBlob = LoadedSealedObject

// Load loads the sealed object and verifies the Name returned by the TPM. A
// failed verification flushes the loaded handle.
func (s *SealedObject) Load(rw io.ReadWriter) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidates := txn.recoveryCandidates()
	var errs []error
	for i, candidate := range candidates {
		loaded, err := txn.loadCandidate(rw, candidate)
		if err == nil {
			return loaded, nil
		}
		errs = append(errs, fmt.Errorf("candidate %d: %w", i, err))
	}
	if len(errs) == 0 {
		return nil, ErrNoSealedObjects
	}
	return nil, fmt.Errorf("%w: all load attempts failed: %w", ErrSealedObject, errors.Join(errs...))
}

// LoadHandle is like Load but returns the raw TPM handle and Name.
func (s *SealedObject) LoadHandle(rw io.ReadWriter) (tpmutil.Handle, []byte, error) {
	loaded, err := s.Load(rw)
	if err != nil {
		return 0, nil, err
	}
	return loaded.Handle, append([]byte(nil), loaded.Name...), nil
}

// LoadWithParent loads the transaction under a different parent. The old
// parent and blob are not modified.
func (s *SealedObject) LoadWithParent(rw io.ReadWriter, parent tpmutil.Handle, parentAuth string) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	txn.Parent = parent
	txn.ParentAuth = parentAuth
	txn.Primary = parent
	txn.ParentHandle = parent
	txn.ParentPassword = parentAuth
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.loadCandidate(rw, txn.recoveryCandidates()[0])
}

// Unseal loads and unseals the sealed object as one recovery transaction. The
// returned data must equal the committed plaintext; otherwise no data is
// returned and the loaded handle is flushed.
func (s *SealedObject) Unseal(rw io.ReadWriter) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidates := txn.recoveryCandidates()
	var errs []error
	for i, candidate := range candidates {
		loaded, err := txn.loadCandidate(rw, candidate)
		if err != nil {
			errs = append(errs, fmt.Errorf("candidate %d: %w", i, err))
			continue
		}
		data, err := loaded.Unseal(rw)
		if err == nil {
			_ = FlushContext(rw, loaded.Handle)
			return data, nil
		}
		errs = append(errs, fmt.Errorf("candidate %d: %w", i, err))
		_ = FlushContext(rw, loaded.Handle)
	}
	if len(errs) == 0 {
		return nil, ErrNoSealedObjects
	}
	return nil, fmt.Errorf("%w: all unseal attempts failed: %w", ErrSealedObject, errors.Join(errs...))
}

// UnsealWithSession unseals with a specific policy session handle.
func (s *SealedObject) UnsealWithSession(rw io.ReadWriter, session tpmutil.Handle) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	txn.Session = session
	return txn.Unseal(rw)
}

// UnsealWithPassword forces password authorization for the sealed object.
func (s *SealedObject) UnsealWithPassword(rw io.ReadWriter) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	txn.Session = 0
	txn.PolicySession = 0
	return txn.Unseal(rw)
}

// Reseal creates a new blob for the same plaintext, password, and PCR policy
// under another parent. The original transaction and blob are left untouched.
func (s *SealedObject) Reseal(rw io.ReadWriter, parent tpmutil.Handle, parentAuth string) (*SealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	sealed, err := SealObject(rw, parent, parentAuth, txn.Auth, txn.Policy, txn.Plaintext)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sealed.Name, txn.Name) {
		return nil, fmt.Errorf(
			"%w: resealed Name %x, original Name %x",
			ErrSealedObjectName, sealed.Name, txn.Name)
	}
	sealed.OldPublic = append([]byte(nil), txn.Public...)
	sealed.OldBlob = append([]byte(nil), txn.Private...)
	sealed.Candidates = append(sealed.Candidates, txn.recoveryCandidates()...)
	if err := sealed.normalize(); err != nil {
		return nil, err
	}
	return sealed, nil
}

// SealUnder is an alias for Reseal.
func (s *SealedObject) SealUnder(rw io.ReadWriter, parent tpmutil.Handle, parentAuth string) (*SealedObject, error) {
	return s.Reseal(rw, parent, parentAuth)
}

// Seal is an alias for Reseal.
func (s *SealedObject) Seal(rw io.ReadWriter, parent tpmutil.Handle, parentAuth string) (*SealedObject, error) {
	return s.Reseal(rw, parent, parentAuth)
}

// Recover is an alias for Unseal.
func (s *SealedObject) Recover(rw io.ReadWriter) ([]byte, error) {
	return s.Unseal(rw)
}

// LoadAndUnseal is an alias for Unseal.
func (s *SealedObject) LoadAndUnseal(rw io.ReadWriter) ([]byte, error) {
	return s.Unseal(rw)
}

// Open is an alias for Unseal.
func (s *SealedObject) Open(rw io.ReadWriter) ([]byte, error) {
	return s.Unseal(rw)
}

// Unseal returns the plaintext of a loaded legacy sealed object and verifies
// it against the transaction plaintext.
func (o *LoadedSealedObject) Unseal(rw io.ReadWriter) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	var data []byte
	var err error
	session := o.Session
	if session == 0 {
		session = o.PolicySession
	}
	if session != 0 {
		data, err = UnsealWithSession(rw, session, o.Handle, o.Auth)
	} else {
		data, err = Unseal(rw, o.Handle, o.Auth)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: unsealing loaded object: %w", ErrSealedObject, err)
	}
	if !bytes.Equal(data, o.Plaintext) {
		_ = FlushContext(rw, o.Handle)
		return nil, fmt.Errorf(
			"%w: unsealed %x, transaction plaintext %x",
			ErrSealedObjectPlaintext, data, o.Plaintext)
	}
	return append([]byte(nil), data...), nil
}

// UnsealWithAuth overrides the loaded object's authorization value.
func (o *LoadedSealedObject) UnsealWithAuth(rw io.ReadWriter, auth string) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	clone := *o
	clone.Auth = auth
	return clone.Unseal(rw)
}

// UnsealWithSession overrides the loaded object's policy session.
func (o *LoadedSealedObject) UnsealWithSession(rw io.ReadWriter, session tpmutil.Handle) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	clone := *o
	clone.Session = session
	clone.PolicySession = session
	return clone.Unseal(rw)
}

// UnsealWithPassword forces password authorization for the loaded object.
func (o *LoadedSealedObject) UnsealWithPassword(rw io.ReadWriter) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	clone := *o
	clone.Session = 0
	clone.PolicySession = 0
	return clone.Unseal(rw)
}

// Flush flushes the loaded handle.
func (o *LoadedSealedObject) Flush(rw io.ReadWriter) error {
	if o == nil || o.Handle == 0 {
		return nil
	}
	if err := FlushContext(rw, o.Handle); err != nil {
		return fmt.Errorf("%w: flushing loaded object: %v", ErrSealedObject, err)
	}
	o.Handle = 0
	o.ObjectHandle = 0
	return nil
}

// LoadFirstSealedObject tries each transaction in order and returns the first
// one that loads successfully.
func LoadFirstSealedObject(rw io.ReadWriter, objects []*SealedObject) (*LoadedSealedObject, error) {
	if len(objects) == 0 {
		return nil, ErrNoSealedObjects
	}
	var errs []error
	for i, object := range objects {
		if object == nil {
			errs = append(errs, fmt.Errorf("sealed object %d: %w", i, ErrSealedObject))
			continue
		}
		loaded, err := object.Load(rw)
		if err == nil {
			return loaded, nil
		}
		errs = append(errs, fmt.Errorf("sealed object %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all sealed objects failed: %w", ErrSealedObject, errors.Join(errs...))
}

// UnsealFirstSealedObject tries each transaction in order and returns the
// plaintext of the first one that loads and unseals its own committed
// plaintext.
func UnsealFirstSealedObject(rw io.ReadWriter, objects []*SealedObject) ([]byte, error) {
	if len(objects) == 0 {
		return nil, ErrNoSealedObjects
	}
	var errs []error
	for i, object := range objects {
		if object == nil {
			errs = append(errs, fmt.Errorf("sealed object %d: %w", i, ErrSealedObject))
			continue
		}
		data, err := object.Unseal(rw)
		if err == nil {
			return data, nil
		}
		errs = append(errs, fmt.Errorf("sealed object %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all sealed objects failed: %w", ErrSealedObject, errors.Join(errs...))
}

func (s *SealedObject) loadCandidate(rw io.ReadWriter, candidate SealedCandidate) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidate = candidate.normalized(txn)
	if candidate.Parent == 0 {
		return nil, ErrSealedObjectParent
	}
	if len(candidate.Public) == 0 {
		return nil, ErrSealedObjectPublic
	}
	if len(candidate.Private) == 0 {
		return nil, ErrSealedObjectPrivate
	}
	expected, err := legacyPublicName(candidate.Public)
	if err != nil {
		return nil, err
	}
	if len(txn.Name) != 0 && !bytes.Equal(txn.Name, expected) {
		return nil, fmt.Errorf(
			"%w: transaction Name %x, candidate public area Name %x",
			ErrSealedObjectMismatch, txn.Name, expected)
	}
	if len(candidate.Name) != 0 && !bytes.Equal(candidate.Name, expected) {
		return nil, fmt.Errorf(
			"%w: candidate Name %x, public area Name %x",
			ErrSealedObjectMismatch, candidate.Name, expected)
	}

	handle, name, err := Load(rw, candidate.Parent, candidate.ParentAuth, candidate.Public, candidate.Private)
	if err != nil {
		if errors.Is(err, ErrObjectNameMismatch) {
			return nil, fmt.Errorf("%w: %w", ErrSealedObjectMismatch, err)
		}
		return nil, fmt.Errorf("%w: loading sealed object: %w", ErrSealedObject, err)
	}
	if !bytes.Equal(name, expected) {
		mismatch := fmt.Errorf(
			"%w: loaded Name %x, transaction Name %x",
			ErrSealedObjectMismatch, name, expected)
		if flushErr := FlushContext(rw, handle); flushErr != nil {
			return nil, fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, handle, flushErr)
		}
		return nil, mismatch
	}
	return &LoadedSealedObject{
		Handle:       handle,
		Name:         append([]byte(nil), expected...),
		Public:       append([]byte(nil), candidate.Public...),
		Private:      append([]byte(nil), candidate.Private...),
		Parent:       candidate.Parent,
		Plaintext:    append([]byte(nil), txn.Plaintext...),
		Auth:         txn.Auth,
		Policy:       append([]byte(nil), txn.Policy...),
		Session:      txn.Session,
		PolicySession: txn.Session,
		ObjectHandle: handle,
		ObjectName:   append([]byte(nil), expected...),
		Data:         append([]byte(nil), txn.Plaintext...),
	}, nil
}

func (s *SealedObject) snapshot() (*SealedObject, error) {
	if s == nil {
		return nil, ErrSealedObject
	}
	txn := s.clone()
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn, nil
}

func (s *SealedObject) clone() *SealedObject {
	txn := &SealedObject{
		Parent:         s.Parent,
		ParentAuth:     s.ParentAuth,
		Public:         append([]byte(nil), s.Public...),
		Private:        append([]byte(nil), s.Private...),
		Name:           append([]byte(nil), s.Name...),
		Plaintext:      append([]byte(nil), s.Plaintext...),
		Auth:           s.Auth,
		Policy:         append([]byte(nil), s.Policy...),
		Session:        s.Session,
		ParentHandle:   s.ParentHandle,
		ParentPassword: s.ParentPassword,
		Primary:        s.Primary,
		PrimaryKey:     s.PrimaryKey,
		SealedPublic:   append([]byte(nil), s.SealedPublic...),
		SealedPrivate:  append([]byte(nil), s.SealedPrivate...),
		ObjectName:     append([]byte(nil), s.ObjectName...),
		Data:           append([]byte(nil), s.Data...),
		Password:       s.Password,
		PCRPolicy:      append([]byte(nil), s.PCRPolicy...),
		PolicySession:  s.PolicySession,
		OldPublic:      append([]byte(nil), s.OldPublic...),
		OldBlob:        append([]byte(nil), s.OldBlob...),
	}
	for _, candidate := range s.Candidates {
		txn.Candidates = append(txn.Candidates, candidate.clone())
	}
	return txn
}

func (s *SealedObject) normalize() error {
	if s == nil {
		return ErrSealedObject
	}
	if s.Parent == 0 {
		s.Parent = s.ParentHandle
	}
	if s.Parent == 0 {
		s.Parent = s.Primary
	}
	if s.Parent == 0 {
		s.Parent = s.PrimaryKey
	}
	if s.ParentHandle == 0 {
		s.ParentHandle = s.Parent
	}
	if s.Primary == 0 {
		s.Primary = s.Parent
	}
	if s.PrimaryKey == 0 {
		s.PrimaryKey = s.Parent
	}
	if s.ParentAuth == "" {
		s.ParentAuth = s.ParentPassword
	}
	s.ParentPassword = s.ParentAuth

	if len(s.Public) == 0 {
		s.Public = append([]byte(nil), s.SealedPublic...)
	}
	if len(s.Private) == 0 {
		s.Private = append([]byte(nil), s.SealedPrivate...)
	}
	if len(s.Name) == 0 {
		s.Name = append([]byte(nil), s.ObjectName...)
	}
	if s.Plaintext == nil {
		s.Plaintext = append([]byte(nil), s.Data...)
	}
	if s.Auth == "" {
		s.Auth = s.Password
	}
	if len(s.Policy) == 0 {
		s.Policy = append([]byte(nil), s.PCRPolicy...)
	}
	if s.Session == 0 {
		s.Session = s.PolicySession
	}
	s.PolicySession = s.Session
	if len(s.OldPublic) == 0 {
		s.OldPublic = append([]byte(nil), s.Public...)
	}
	if len(s.OldBlob) == 0 {
		s.OldBlob = append([]byte(nil), s.Private...)
	}
	s.SealedPublic = append([]byte(nil), s.Public...)
	s.SealedPrivate = append([]byte(nil), s.Private...)
	s.ObjectName = append([]byte(nil), s.Name...)
	s.Data = append([]byte(nil), s.Plaintext...)
	s.Password = s.Auth
	s.PCRPolicy = append([]byte(nil), s.Policy...)

	if s.Parent == 0 {
		return ErrSealedObjectParent
	}
	if len(s.Public) == 0 {
		return ErrSealedObjectPublic
	}
	name, err := legacyPublicName(s.Public)
	if err != nil {
		return err
	}
	if len(s.Name) == 0 {
		s.Name = name
		s.ObjectName = append([]byte(nil), name...)
	} else if !bytes.Equal(s.Name, name) {
		return fmt.Errorf("%w: supplied %x, public area %x", ErrSealedObjectName, s.Name, name)
	}
	if len(s.Policy) == 0 {
		if pub, err := DecodePublic(s.Public); err == nil {
			s.Policy = append([]byte(nil), []byte(pub.AuthPolicy)...)
			s.PCRPolicy = append([]byte(nil), []byte(pub.AuthPolicy)...)
		}
	}
	for i := range s.Candidates {
		s.Candidates[i] = s.Candidates[i].normalized(s)
	}
	return nil
}

func (s *SealedObject) recoveryCandidates() []SealedCandidate {
	primary := SealedCandidate{
		Parent:     s.Parent,
		ParentAuth: s.ParentAuth,
		Public:     append([]byte(nil), s.Public...),
		Private:    append([]byte(nil), s.Private...),
		Name:       append([]byte(nil), s.Name...),
	}
	result := []SealedCandidate{primary}
	if len(s.OldBlob) != 0 && !bytes.Equal(s.OldBlob, s.Private) {
		oldPublic := s.OldPublic
		if len(oldPublic) == 0 {
			oldPublic = s.Public
		}
		result = append(result, SealedCandidate{
			Parent:     s.Parent,
			ParentAuth: s.ParentAuth,
			Public:     append([]byte(nil), oldPublic...),
			Private:    append([]byte(nil), s.OldBlob...),
		})
	}
	for _, candidate := range s.Candidates {
		result = append(result, candidate.clone())
	}
	return result
}

func (c SealedCandidate) normalized(txn *SealedObject) SealedCandidate {
	candidate := c.clone()
	if candidate.Parent == 0 {
		candidate.Parent = txn.Parent
	}
	if candidate.ParentAuth == "" {
		candidate.ParentAuth = txn.ParentAuth
	}
	if len(candidate.Public) == 0 {
		candidate.Public = append([]byte(nil), txn.Public...)
	}
	if len(candidate.Private) == 0 {
		candidate.Private = append([]byte(nil), txn.Private...)
	}
	if len(candidate.Name) == 0 {
		candidate.Name = append([]byte(nil), txn.Name...)
	}
	return candidate
}

func (c SealedCandidate) clone() SealedCandidate {
	return SealedCandidate{
		Parent:     c.Parent,
		ParentAuth: c.ParentAuth,
		Public:     append([]byte(nil), c.Public...),
		Private:    append([]byte(nil), c.Private...),
		Name:       append([]byte(nil), c.Name...),
		Plaintext:  append([]byte(nil), c.Plaintext...),
		Auth:       c.Auth,
		Policy:     append([]byte(nil), c.Policy...),
	}
}

func legacyPublicName(public []byte) ([]byte, error) {
	pub, err := DecodePublic(public)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding public area: %v", ErrSealedObjectPublic, err)
	}
	name, err := pub.Name()
	if err != nil {
		return nil, fmt.Errorf("%w: computing object Name: %v", ErrSealedObjectName, err)
	}
	encoded, err := name.Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: encoding object Name: %v", ErrSealedObjectName, err)
	}
	return encoded, nil
}

func verifyLoadName(rw io.ReadWriter, public []byte, name []byte, handle tpmutil.Handle) error {
	pub, err := DecodePublic(public)
	if err != nil {
		// Preserve the previous behavior for opaque public areas. The TPM is
		// still responsible for validating the marshalled public area.
		return nil
	}
	canonical, err := pub.Encode()
	if err != nil || !bytes.Equal(canonical, public) {
		// The caller supplied a non-canonical encoding. Do not reject it here.
		return nil
	}
	nameValue, err := pub.Name()
	if err != nil {
		return nil
	}
	expected, err := nameValue.Encode()
	if err != nil {
		return nil
	}
	if bytes.Equal(name, expected) {
		return nil
	}
	mismatch := fmt.Errorf(
		"%w: loaded Name %x, public area Name %x",
		ErrObjectNameMismatch, name, expected)
	if flushErr := FlushContext(rw, handle); flushErr != nil {
		return fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, handle, flushErr)
	}
	return mismatch
}

func looksLikeName(value []byte) bool {
	buf := bytes.NewBuffer(value)
	name, err := DecodeName(buf)
	if err != nil || buf.Len() != 0 {
		return false
	}
	encoded, err := name.Encode()
	return err == nil && bytes.Equal(encoded, value)
}
