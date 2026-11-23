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

	"github.com/google/go-tpm/tpm2/transport"
)

// Errors returned by the sealed-object transaction helpers. Callers can use
// errors.Is with ErrSealedObject to match any failure from this file.
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
	// ErrSealedObjectAlreadyLoaded means that a one-shot loaded object was
	// already claimed.
	ErrSealedObjectAlreadyLoaded = fmt.Errorf("%w: sealed object was already loaded", ErrSealedObject)
	// ErrNoSealedObjects means that no sealed-object candidates were supplied.
	ErrNoSealedObjects = fmt.Errorf("%w: no sealed object candidates", ErrSealedObject)

	// ErrObjectNameMismatch is returned by Load when the TPM returns a handle
	// whose Name does not identify the requested public area. The handle is
	// flushed before this error is returned.
	ErrObjectNameMismatch = errors.New("tpm2: object Name does not match its public area")
)

// SealedParent is the parent under which a sealed object is loaded. It may be
// a TPMHandle, NamedHandle, or AuthHandle.
type SealedParent interface {
	HandleValue() uint32
	KnownName() *TPM2BName
}

// SealedCandidate is one recovery candidate for a SealedObject. Every
// candidate carries its own parent, public area, private area, and Name so a
// retry can never combine the parent from one object with the blob from
// another. Empty fields are inherited from the enclosing SealedObject.
type SealedCandidate struct {
	// Parent is the parent used to load this candidate.
	Parent SealedParent
	// Public is the public area of this candidate.
	Public TPM2BPublic
	// Private is the private area of this candidate.
	Private TPM2BPrivate
	// Name is the TPM Name of Public.
	Name TPM2BName
	// Plaintext, Auth, and Policy are optional per-candidate commitments.
	// When set, they must agree with the enclosing transaction.
	Plaintext []byte
	Auth      []byte
	Policy    TPM2BDigest

	// Primary is an alias for Parent.
	Primary SealedParent
	// InPublic is an alias for Public.
	InPublic TPM2BPublic
	// InPrivate is an alias for Private.
	InPrivate TPM2BPrivate
	// ObjectName is an alias for Name.
	ObjectName TPM2BName
}

// SealedObject binds every piece of state needed to move and use one sealed
// value: the sealed public/private areas, their TPM Name, the parent, the
// object password, the PCR policy, and the expected plaintext. Load and
// Unseal always use the state from the same SealedObject. A load retry or a
// parent switch therefore cannot accidentally attribute the plaintext of a
// different object to the current sealed blob.
//
// A SealedObject is a snapshot. Construct it with NewSealedObject, SealObject,
// or one of the Seal* helpers so its byte slices do not alias caller-owned
// buffers. Methods clone their inputs again, so the original blob remains
// usable after a failed or successful load.
type SealedObject struct {
	// Parent is the parent under which this blob is loaded.
	Parent SealedParent
	// ParentName is the Name of Parent when Parent itself does not carry it.
	ParentName TPM2BName
	// ParentAuth is the authorization value of Parent.
	ParentAuth []byte
	// Public is the public area of the sealed object.
	Public TPM2BPublic
	// Private is the private area of the sealed object.
	Private TPM2BPrivate
	// Name is the TPM Name of Public.
	Name TPM2BName
	// Plaintext is the data committed to by this transaction.
	Plaintext []byte
	// Auth is the authorization value of the sealed object.
	Auth []byte
	// Policy is the PCR policy digest that protects the sealed object.
	Policy TPM2BDigest
	// Session is an optional authorization session for Unseal.
	Session Session
	// Candidates are additional recovery candidates. They are tried in order
	// after the primary (Parent/Public/Private/Name) candidate.
	Candidates []SealedCandidate

	// Primary is an alias for Parent.
	Primary SealedParent
	// ParentHandle is an alias for Parent.
	ParentHandle SealedParent
	// Key, PrimaryKey, and ParentKey are aliases for Parent.
	Key        SealedParent
	PrimaryKey SealedParent
	ParentKey  SealedParent
	// ParentPassword is an alias for ParentAuth.
	ParentPassword []byte
	// ParentHandleName is an alias for ParentName.
	ParentHandleName TPM2BName

	// InPublic, OutPublic, and SealedPublic are aliases for Public.
	InPublic     TPM2BPublic
	OutPublic    TPM2BPublic
	SealedPublic TPM2BPublic
	// InPrivate, OutPrivate, and SealedPrivate are aliases for Private.
	InPrivate     TPM2BPrivate
	OutPrivate    TPM2BPrivate
	SealedPrivate TPM2BPrivate
	// ObjectName is an alias for Name.
	ObjectName TPM2BName
	// Data and Secret are aliases for Plaintext.
	Data      []byte
	Secret    []byte
	PlainText []byte
	// Password and ObjectAuth are aliases for Auth.
	Password       []byte
	ObjectAuth     []byte
	ObjectPassword []byte
	// PCRPolicy and AuthPolicy are aliases for Policy.
	PCRPolicy  TPM2BDigest
	AuthPolicy TPM2BDigest
	// PolicySession is an alias for Session.
	PolicySession Session
	// OldPublic and OldBlob retain the previous blob without consuming it.
	OldPublic TPM2BPublic
	OldBlob   TPM2BPrivate
}

// SealedBlob, SealingTransaction, and SealTransaction are aliases for
// SealedObject so callers can use the terminology that fits their application.
type SealedBlob = SealedObject

// SealingTransaction is an alias for SealedObject.
type SealingTransaction = SealedObject

// SealTransaction is an alias for SealedObject.
type SealTransaction = SealedObject

// SealedObjectTransaction is an alias for SealedObject.
type SealedObjectTransaction = SealedObject

// RecoveryTransaction is an alias for SealedObject.
type RecoveryTransaction = SealedObject

// Recovery is an alias for SealedObject.
type Recovery = SealedObject

// Sealed and SealedData are aliases for SealedObject.
type Sealed = SealedObject

// SealedData is an alias for SealedObject.
type SealedData = SealedObject

// NewSealedObject builds a sealed-object transaction from its parts.
//
// Arguments may be supplied in the order (public, private, name, parent,
// plaintext, auth, policy) or (parent, public, private, name, plaintext, auth,
// policy). Typed values remove any ambiguity; untyped []byte arguments are
// assigned to plaintext, auth, and policy in that order after the typed
// values have been consumed.
func NewSealedObject(args ...any) (*SealedObject, error) {
	s := &SealedObject{}
	var byteArgs [][]byte

	for _, arg := range args {
		switch v := arg.(type) {
		case nil:
			// Ignore nil optional values.
		case *AuthHandle:
			if v == nil {
				continue
			}
			s.setParent(*v)
		case *NamedHandle:
			if v == nil {
				continue
			}
			s.setParent(*v)
		case SealedParent:
			s.setParent(v)
		case TPM2BPublic:
			s.Public = cloneSealedPublic(v)
		case *TPM2BPublic:
			if v != nil {
				s.Public = cloneSealedPublic(*v)
			}
		case TPMTPublic:
			s.Public = cloneSealedPublic(New2B(v))
		case *TPMTPublic:
			if v != nil {
				s.Public = cloneSealedPublic(New2B(*v))
			}
		case TPM2BPrivate:
			s.Private = cloneSealedPrivate(v)
		case *TPM2BPrivate:
			if v != nil {
				s.Private = cloneSealedPrivate(*v)
			}
		case TPM2BName:
			s.Name = cloneSealedName(v)
		case *TPM2BName:
			if v != nil {
				s.Name = cloneSealedName(*v)
			}
		case TPM2BDigest:
			s.Policy = cloneSealedDigest(v)
		case *TPM2BDigest:
			if v != nil {
				s.Policy = cloneSealedDigest(*v)
			}
		case TPM2BAuth:
			if s.Auth == nil {
				s.Auth = cloneSealedBytes(v.Buffer)
			}
		case *TPM2BAuth:
			if v != nil && s.Auth == nil {
				s.Auth = cloneSealedBytes(v.Buffer)
			}
		case TPM2BSensitiveData:
			s.Plaintext = cloneSealedBytes(v.Buffer)
		case *TPM2BSensitiveData:
			if v != nil {
				s.Plaintext = cloneSealedBytes(v.Buffer)
			}
		case TPM2BData:
			byteArgs = append(byteArgs, v.Buffer)
		case *TPM2BData:
			if v != nil {
				byteArgs = append(byteArgs, v.Buffer)
			}
		case []byte:
			byteArgs = append(byteArgs, v)
		case Session:
			s.Session = v
		case string:
			if s.ParentAuth == nil {
				s.ParentAuth = []byte(v)
			} else {
				s.Auth = []byte(v)
			}
		case *CreateResponse:
			if v != nil {
				s.Public = cloneSealedPublic(v.OutPublic)
				s.Private = cloneSealedPrivate(v.OutPrivate)
			}
		case CreateResponse:
			s.Public = cloneSealedPublic(v.OutPublic)
			s.Private = cloneSealedPrivate(v.OutPrivate)
		case *CreateLoadedResponse:
			if v != nil {
				s.Public = cloneSealedPublic(v.OutPublic)
				s.Private = cloneSealedPrivate(v.OutPrivate)
				s.Name = cloneSealedName(v.Name)
			}
		case CreateLoadedResponse:
			s.Public = cloneSealedPublic(v.OutPublic)
			s.Private = cloneSealedPrivate(v.OutPrivate)
			s.Name = cloneSealedName(v.Name)
		case *CreatePrimaryResponse:
			if v != nil {
				s.setParent(AuthHandle{
					Handle: v.ObjectHandle,
					Name:   cloneSealedName(v.Name),
					Auth:   PasswordAuth(nil),
				})
				if len(s.Public.Bytes()) == 0 {
					s.Public = cloneSealedPublic(v.OutPublic)
				}
				if len(s.Name.Buffer) == 0 {
					s.Name = cloneSealedName(v.Name)
				}
			}
		case CreatePrimaryResponse:
			s.setParent(AuthHandle{
				Handle: v.ObjectHandle,
				Name:   cloneSealedName(v.Name),
				Auth:   PasswordAuth(nil),
			})
			if len(s.Public.Bytes()) == 0 {
				s.Public = cloneSealedPublic(v.OutPublic)
			}
			if len(s.Name.Buffer) == 0 {
				s.Name = cloneSealedName(v.Name)
			}
		case *ReadPublicResponse:
			if v != nil {
				s.Public = cloneSealedPublic(v.OutPublic)
				s.Name = cloneSealedName(v.Name)
			}
		case ReadPublicResponse:
			s.Public = cloneSealedPublic(v.OutPublic)
			s.Name = cloneSealedName(v.Name)
		case *LoadResponse:
			if v != nil {
				s.Name = cloneSealedName(v.Name)
			}
		case LoadResponse:
			s.Name = cloneSealedName(v.Name)
		default:
			return nil, fmt.Errorf("%w: unsupported constructor argument %T", ErrSealedObject, arg)
		}
	}

	if s.Plaintext == nil && len(byteArgs) != 0 {
		s.Plaintext = cloneSealedBytes(byteArgs[0])
		byteArgs = byteArgs[1:]
	}
	if s.Auth == nil && len(byteArgs) != 0 {
		s.Auth = cloneSealedBytes(byteArgs[0])
		byteArgs = byteArgs[1:]
	}
	if len(s.Policy.Buffer) == 0 && len(byteArgs) != 0 {
		s.Policy = TPM2BDigest{Buffer: cloneSealedBytes(byteArgs[0])}
		byteArgs = byteArgs[1:]
	}
	if len(byteArgs) != 0 {
		return nil, fmt.Errorf("%w: too many byte arguments", ErrSealedObject)
	}

	if err := s.normalize(); err != nil {
		return nil, err
	}
	if len(s.Private.Buffer) == 0 {
		return nil, ErrSealedObjectPrivate
	}
	return s, nil
}

// NewSealedBlob is an alias for NewSealedObject.
func NewSealedBlob(args ...any) (*SealedBlob, error) {
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

// NewRecoveryTransaction is an alias for NewSealedObject.
func NewRecoveryTransaction(args ...any) (*RecoveryTransaction, error) {
	return NewSealedObject(args...)
}

// NewSealedObjectTransaction is an alias for NewSealedObject.
func NewSealedObjectTransaction(args ...any) (*SealedObjectTransaction, error) {
	return NewSealedObject(args...)
}

// NewSealedData is an alias for NewSealedObject.
func NewSealedData(args ...any) (*SealedData, error) {
	return NewSealedObject(args...)
}

// NewSealed is an alias for NewSealedObject.
func NewSealed(args ...any) (*Sealed, error) {
	return NewSealedObject(args...)
}

// NewRecovery is an alias for NewSealedObject.
func NewRecovery(args ...any) (*Recovery, error) {
	return NewSealedObject(args...)
}

// NewSealedObjectFromCreate builds a transaction from the output of
// TPM2_Create. plaintext, auth, and policy are committed to the transaction.
func NewSealedObjectFromCreate(parent SealedParent, rsp *CreateResponse, plaintext, auth, policy []byte) (*SealedObject, error) {
	if rsp == nil {
		return nil, fmt.Errorf("%w: nil Create response", ErrSealedObject)
	}
	return NewSealedObject(
		parent,
		cloneSealedPublic(rsp.OutPublic),
		cloneSealedPrivate(rsp.OutPrivate),
		cloneSealedBytes(plaintext),
		cloneSealedBytes(auth),
		cloneSealedBytes(policy),
	)
}

// NewSealedObjectFromPublic builds a transaction from already separated
// sealed public and private areas.
func NewSealedObjectFromPublic(parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName, plaintext, auth []byte, policy ...[]byte) (*SealedObject, error) {
	args := []any{
		parent,
		cloneSealedPublic(public),
		cloneSealedPrivate(private),
		cloneSealedName(name),
		cloneSealedBytes(plaintext),
		cloneSealedBytes(auth),
	}
	for _, p := range policy {
		args = append(args, cloneSealedBytes(p))
	}
	return NewSealedObject(args...)
}

// SealObject creates a sealed blob and returns the complete transaction. The
// parent is supplied by the caller, so an existing primary/key is preserved.
// The password, PCR policy, Name, and sealed blob are all committed to the
// returned transaction. If template has a zero Type, a standard sealed-data
// template is used.
func SealObject(t transport.TPM, parent SealedParent, template TPMTPublic, plaintext, auth, policy []byte, sessions ...Session) (*SealedObject, error) {
	if parent == nil {
		return nil, ErrSealedObjectParent
	}
	if template.Type == 0 {
		template = defaultSealedTemplate()
	}
	if len(policy) != 0 {
		template.AuthPolicy = TPM2BDigest{Buffer: cloneSealedBytes(policy)}
	}
	parentHandle, err := candidateParent(parent, &SealedObject{Parent: parent})
	if err != nil {
		return nil, err
	}

	create := Create{
		ParentHandle: parentHandle,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{Buffer: cloneSealedBytes(auth)},
				Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{
					Buffer: cloneSealedBytes(plaintext),
				}),
			},
		},
		InPublic: New2B(template),
	}
	rsp, err := create.Execute(t, sessions...)
	if err != nil {
		return nil, fmt.Errorf("%w: creating sealed blob: %w", ErrSealedObject, err)
	}
	name, err := sealedPublicName(rsp.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealedObjectPublic, err)
	}

	sealed := &SealedObject{
		Parent:    parent,
		Public:    cloneSealedPublic(rsp.OutPublic),
		Private:   cloneSealedPrivate(rsp.OutPrivate),
		Name:      name,
		Plaintext: cloneSealedBytes(plaintext),
		Auth:      cloneSealedBytes(auth),
		Policy:    TPM2BDigest{Buffer: cloneSealedBytes(policy)},
	}
	if err := sealed.normalize(); err != nil {
		return nil, err
	}
	return sealed, nil
}

// SealBlob is an alias for SealObject.
func SealBlob(t transport.TPM, parent SealedParent, template TPMTPublic, plaintext, auth, policy []byte, sessions ...Session) (*SealedBlob, error) {
	return SealObject(t, parent, template, plaintext, auth, policy, sessions...)
}

// SealSealedObject is an alias for SealObject.
func SealSealedObject(t transport.TPM, parent SealedParent, template TPMTPublic, plaintext, auth, policy []byte, sessions ...Session) (*SealedObject, error) {
	return SealObject(t, parent, template, plaintext, auth, policy, sessions...)
}

// CreateSealedObject is an alias for SealObject.
func CreateSealedObject(t transport.TPM, parent SealedParent, template TPMTPublic, plaintext, auth, policy []byte, sessions ...Session) (*SealedObject, error) {
	return SealObject(t, parent, template, plaintext, auth, policy, sessions...)
}

// Seal is an alias for SealObject.
func Seal(t transport.TPM, parent SealedParent, template TPMTPublic, plaintext, auth, policy []byte, sessions ...Session) (*SealedObject, error) {
	return SealObject(t, parent, template, plaintext, auth, policy, sessions...)
}

// defaultSealedTemplate returns a conventional sealed-data template. It is
// only used by SealObject when the caller does not supply a template.
func defaultSealedTemplate() TPMTPublic {
	return TPMTPublic{
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
}

// LoadedSealedObject is a loaded sealed object whose handle, Name, public and
// private areas, parent, and expected plaintext all come from one
// SealedObject transaction.
type LoadedSealedObject struct {
	Handle    TPMHandle
	Name      TPM2BName
	Public    TPM2BPublic
	Private   TPM2BPrivate
	Parent    SealedParent
	Plaintext []byte
	Auth      []byte
	Policy    TPM2BDigest
	Session   Session
	// PolicySession is an alias for Session.
	PolicySession Session

	// ObjectHandle and ObjectName are aliases for Handle and Name.
	ObjectHandle TPMHandle
	ObjectName   TPM2BName
	// Data is an alias for Plaintext.
	Data []byte
}

// LoadedSealedBlob and LoadedBlob are aliases for LoadedSealedObject.
type LoadedSealedBlob = LoadedSealedObject

// LoadedBlob is an alias for LoadedSealedObject.
type LoadedBlob = LoadedSealedObject

// Load loads the sealed object and verifies that the TPM returned an object
// with the Name committed to by this transaction. Additional candidates are
// tried in order after the primary candidate. A loaded handle from a failed
// verification is flushed before the error is returned.
func (s *SealedObject) Load(t transport.TPM, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}

	candidates := txn.recoveryCandidates()
	unsealSessions := sessions
	if len(unsealSessions) == 0 && txn.Session != nil {
		unsealSessions = []Session{txn.Session}
	}
	var errs []error
	for i, candidate := range candidates {
		loaded, err := txn.loadCandidate(t, candidate, sessions...)
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

// LoadPrimary loads only the primary candidate of the transaction.
func (s *SealedObject) LoadPrimary(t transport.TPM, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidate := txn.recoveryCandidates()[0]
	return txn.loadCandidate(t, candidate, sessions...)
}

// LoadVerified loads the sealed object and reads its public area back from the
// TPM. The loaded handle is flushed unless the read-back public area and Name
// both match the transaction.
func (s *SealedObject) LoadVerified(t transport.TPM, sessions ...Session) (*LoadedSealedObject, error) {
	loaded, err := s.Load(t, sessions...)
	if err != nil {
		return nil, err
	}
	readRsp, err := ReadPublic{ObjectHandle: loaded.Handle}.Execute(t)
	if err != nil {
		_ = loaded.Flush(t)
		return nil, fmt.Errorf("%w: reading back sealed object: %v", ErrSealedObject, err)
	}
	if !bytes.Equal(readRsp.Name.Buffer, loaded.Name.Buffer) ||
		!bytes.Equal(readRsp.OutPublic.Bytes(), loaded.Public.Bytes()) {
		_ = loaded.Flush(t)
		return nil, fmt.Errorf("%w: read-back public area or Name does not match", ErrSealedObjectMismatch)
	}
	return loaded, nil
}

// LoadWithParent loads the transaction using a different parent. The old
// parent and blob are not modified. The TPM must still accept the sealed blob
// under that parent, and the returned Name and plaintext remain bound to this
// transaction.
func (s *SealedObject) LoadWithParent(t transport.TPM, parent SealedParent, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	replaceSealedParent(txn, parent)
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.LoadPrimary(t, sessions...)
}

// LoadWithAuth loads the transaction using auth as the parent's
// authorization session. Any additional sessions are extra sessions.
func (s *SealedObject) LoadWithAuth(t transport.TPM, auth Session, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	if txn.Parent == nil {
		return nil, ErrSealedObjectParent
	}
	name := cloneSealedName(txn.ParentName)
	if len(name.Buffer) == 0 {
		if known := txn.Parent.KnownName(); known != nil {
			name = cloneSealedName(*known)
		}
	}
	txn.Parent = AuthHandle{
		Handle: TPMHandle(txn.Parent.HandleValue()),
		Name:   name,
		Auth:   auth,
	}
	txn.ParentName = name
	txn.Primary = txn.Parent
	txn.ParentHandle = txn.Parent
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.LoadPrimary(t, sessions...)
}

// LoadWithParentAuth loads the transaction under parent using auth as the
// parent's password.
func (s *SealedObject) LoadWithParentAuth(t transport.TPM, parent SealedParent, auth []byte, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	replaceSealedParent(txn, parent)
	txn.ParentAuth = cloneSealedBytes(auth)
	if txn.Parent == nil {
		return nil, ErrSealedObjectParent
	}
	name := cloneSealedName(txn.ParentName)
	if len(name.Buffer) == 0 {
		if known := txn.Parent.KnownName(); known != nil {
			name = cloneSealedName(*known)
		}
	}
	txn.Parent = AuthHandle{
		Handle: TPMHandle(txn.Parent.HandleValue()),
		Name:   name,
		Auth:   PasswordAuth(cloneSealedBytes(auth)),
	}
	txn.Primary = txn.Parent
	txn.ParentHandle = txn.Parent
	txn.ParentName = name
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.LoadPrimary(t, sessions...)
}

// LoadWithSession is an alias for LoadWithAuth.
func (s *SealedObject) LoadWithSession(t transport.TPM, session Session, sessions ...Session) (*LoadedSealedObject, error) {
	return s.LoadWithAuth(t, session, sessions...)
}

// LoadWithParents tries the transaction's own blob under each parent in
// order. Every attempt starts from the same public/private areas, Name, and
// expected plaintext.
func (s *SealedObject) LoadWithParents(t transport.TPM, parents []SealedParent, sessions ...Session) (*LoadedSealedObject, error) {
	if len(parents) == 0 {
		return nil, ErrSealedObjectParent
	}
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	var errs []error
	for i, parent := range parents {
		attempt := txn.clone()
		replaceSealedParent(attempt, parent)
		if err := attempt.normalize(); err != nil {
			errs = append(errs, fmt.Errorf("parent %d: %w", i, err))
			continue
		}
		loaded, err := attempt.LoadPrimary(t, sessions...)
		if err == nil {
			return loaded, nil
		}
		errs = append(errs, fmt.Errorf("parent %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all parent attempts failed: %w", ErrSealedObject, errors.Join(errs...))
}

// LoadFirst is an alias for LoadWithParents.
func (s *SealedObject) LoadFirst(t transport.TPM, parents []SealedParent, sessions ...Session) (*LoadedSealedObject, error) {
	return s.LoadWithParents(t, parents, sessions...)
}

// Retry retries loading the same transaction under the supplied parents.
func (s *SealedObject) Retry(t transport.TPM, parents []SealedParent, sessions ...Session) (*LoadedSealedObject, error) {
	return s.LoadWithParents(t, parents, sessions...)
}

// Unseal loads and unseals the sealed object as one recovery transaction. The
// returned data must equal the plaintext committed to at construction time;
// otherwise no data is returned and the loaded handle is flushed.
func (s *SealedObject) Unseal(t transport.TPM, sessions ...Session) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidates := txn.recoveryCandidates()
	var errs []error
	for i, candidate := range candidates {
		loaded, err := txn.loadCandidate(t, candidate)
		if err != nil {
			errs = append(errs, fmt.Errorf("candidate %d: %w", i, err))
			continue
		}
		data, err := loaded.Unseal(t, unsealSessions...)
		if err == nil {
			_ = loaded.Flush(t)
			return data, nil
		}
		errs = append(errs, fmt.Errorf("candidate %d: %w", i, err))
		// A plaintext or response mismatch flushes the handle. Flush is
		// idempotent, so clean up handles that failed for other reasons too.
		_ = loaded.Flush(t)
	}
	if len(errs) == 0 {
		return nil, ErrNoSealedObjects
	}
	return nil, fmt.Errorf("%w: all unseal attempts failed: %w", ErrSealedObject, errors.Join(errs...))
}

// LoadAndUnseal is an alias for Unseal.
func (s *SealedObject) LoadAndUnseal(t transport.TPM, sessions ...Session) ([]byte, error) {
	return s.Unseal(t, sessions...)
}

// Open is an alias for Unseal.
func (s *SealedObject) Open(t transport.TPM, sessions ...Session) ([]byte, error) {
	return s.Unseal(t, sessions...)
}

// Recover is an alias for Unseal.
func (s *SealedObject) Recover(t transport.TPM, sessions ...Session) ([]byte, error) {
	return s.Unseal(t, sessions...)
}

// UnsealWithAuth overrides the sealed object's authorization value for this
// attempt without changing the transaction.
func (s *SealedObject) UnsealWithAuth(t transport.TPM, auth []byte, sessions ...Session) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	txn.Auth = cloneSealedBytes(auth)
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.Unseal(t, sessions...)
}

// UnsealWithPassword forces password authorization for the sealed object.
func (s *SealedObject) UnsealWithPassword(t transport.TPM, sessions ...Session) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	txn.Session = nil
	txn.PolicySession = nil
	return txn.Unseal(t, sessions...)
}

// UnsealWithLoadSession uses loadSession to authorize the parent for Load and
// then unseals with unsealSessions (the first of which authorizes the sealed
// object itself).
func (s *SealedObject) UnsealWithLoadSession(t transport.TPM, loadSession Session, unsealSessions ...Session) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	if txn.Parent == nil {
		return nil, ErrSealedObjectParent
	}
	name := cloneSealedName(txn.ParentName)
	if len(name.Buffer) == 0 {
		if known := txn.Parent.KnownName(); known != nil {
			name = cloneSealedName(*known)
		}
	}
	txn.Parent = AuthHandle{
		Handle: TPMHandle(txn.Parent.HandleValue()),
		Name:   name,
		Auth:   loadSession,
	}
	txn.Primary = txn.Parent
	txn.ParentHandle = txn.Parent
	txn.ParentName = name
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.Unseal(t, unsealSessions...)
}

// UnsealWithPolicy authorizes the sealed object with policy and treats any
// additional sessions as extra sessions.
func (s *SealedObject) UnsealWithPolicy(t transport.TPM, policy Session, sessions ...Session) ([]byte, error) {
	all := make([]Session, 0, 1+len(sessions))
	all = append(all, policy)
	all = append(all, sessions...)
	return s.Unseal(t, all...)
}

// UnsealWithSession is an alias for UnsealWithPolicy.
func (s *SealedObject) UnsealWithSession(t transport.TPM, session Session, sessions ...Session) ([]byte, error) {
	return s.UnsealWithPolicy(t, session, sessions...)
}

// UnsealWithParent loads and unseals the transaction using a different parent.
func (s *SealedObject) UnsealWithParent(t transport.TPM, parent SealedParent, sessions ...Session) ([]byte, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	replaceSealedParent(txn, parent)
	if err := txn.normalize(); err != nil {
		return nil, err
	}
	return txn.Unseal(t, sessions...)
}

// UnsealWithParentAuth loads and unseals using parent and its password.
func (s *SealedObject) UnsealWithParentAuth(t transport.TPM, parent SealedParent, auth []byte, sessions ...Session) ([]byte, error) {
	loaded, err := s.LoadWithParentAuth(t, parent, auth)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = loaded.Flush(t)
	}()
	return loaded.Unseal(t, sessions...)
}

// UnsealWithParentPassword is an alias for UnsealWithParentAuth.
func (s *SealedObject) UnsealWithParentPassword(t transport.TPM, parent SealedParent, auth []byte, sessions ...Session) ([]byte, error) {
	return s.UnsealWithParentAuth(t, parent, auth, sessions...)
}

// UnsealWithParents tries each parent in order and returns the data from the
// first candidate that both loads and unseals the expected plaintext.
func (s *SealedObject) UnsealWithParents(t transport.TPM, parents []SealedParent, sessions ...Session) ([]byte, error) {
	if len(parents) == 0 {
		return nil, ErrSealedObjectParent
	}
	var errs []error
	for i, parent := range parents {
		data, err := s.UnsealWithParent(t, parent, sessions...)
		if err == nil {
			return data, nil
		}
		errs = append(errs, fmt.Errorf("parent %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all parent unseal attempts failed: %w", ErrSealedObject, errors.Join(errs...))
}

// Reseal creates a new sealed blob for the same plaintext, password, and PCR
// policy under a different parent. The original transaction and its blob are
// left untouched and are retained as recovery candidates in the result.
func (s *SealedObject) Reseal(t transport.TPM, parent SealedParent, sessions ...Session) (*SealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	template := defaultSealedTemplate()
	if contents, err := Unmarshal[TPMTPublic](txn.Public.Bytes()); err == nil {
		template = *contents
	}
	template.AuthPolicy = cloneSealedDigest(txn.Policy)

	sealed, err := SealObject(t, parent, template, txn.Plaintext, txn.Auth, txn.Policy.Buffer, sessions...)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sealed.Name.Buffer, txn.Name.Buffer) {
		return nil, fmt.Errorf(
			"%w: resealed Name %x, original Name %x",
			ErrSealedObjectName, sealed.Name.Buffer, txn.Name.Buffer)
	}
	sealed.OldPublic = cloneSealedPublic(txn.Public)
	sealed.OldBlob = cloneSealedPrivate(txn.Private)
	sealed.Candidates = append(sealed.Candidates, txn.recoveryCandidates()...)
	if err := sealed.normalize(); err != nil {
		return nil, err
	}
	return sealed, nil
}

// SealUnder is an alias for Reseal.
func (s *SealedObject) SealUnder(t transport.TPM, parent SealedParent, sessions ...Session) (*SealedObject, error) {
	return s.Reseal(t, parent, sessions...)
}

// Seal is an alias for Reseal.
func (s *SealedObject) Seal(t transport.TPM, parent SealedParent, sessions ...Session) (*SealedObject, error) {
	return s.Reseal(t, parent, sessions...)
}

// PublicArea returns a copy of the sealed public area.
func (s *SealedObject) PublicArea() TPM2BPublic {
	if s == nil {
		return TPM2BPublic{}
	}
	return cloneSealedPublic(s.Public)
}

// PrivateArea returns a copy of the sealed private area.
func (s *SealedObject) PrivateArea() TPM2BPrivate {
	if s == nil {
		return TPM2BPrivate{}
	}
	return cloneSealedPrivate(s.Private)
}

// ObjectNameValue returns a copy of the transaction's object Name.
func (s *SealedObject) ObjectNameValue() TPM2BName {
	if s == nil {
		return TPM2BName{}
	}
	return cloneSealedName(s.Name)
}

// SecretValue returns a copy of the committed plaintext.
func (s *SealedObject) SecretValue() []byte {
	if s == nil {
		return nil
	}
	return cloneSealedBytes(s.Plaintext)
}

// PasswordValue returns a copy of the sealed object's authorization value.
func (s *SealedObject) PasswordValue() []byte {
	if s == nil {
		return nil
	}
	return cloneSealedBytes(s.Auth)
}

// PCRPolicyValue returns a copy of the PCR policy digest.
func (s *SealedObject) PCRPolicyValue() TPM2BDigest {
	if s == nil {
		return TPM2BDigest{}
	}
	return cloneSealedDigest(s.Policy)
}

// PrimaryHandle returns the parent of the transaction.
func (s *SealedObject) PrimaryHandle() SealedParent {
	if s == nil {
		return nil
	}
	return s.Parent
}

// Blob returns copies of the public and private areas.
func (s *SealedObject) Blob() (TPM2BPublic, TPM2BPrivate) {
	if s == nil {
		return TPM2BPublic{}, TPM2BPrivate{}
	}
	return cloneSealedPublic(s.Public), cloneSealedPrivate(s.Private)
}

// OldBlobValue returns the retained previous private area, if any.
func (s *SealedObject) OldBlobValue() TPM2BPrivate {
	if s == nil {
		return TPM2BPrivate{}
	}
	return cloneSealedPrivate(s.OldBlob)
}

// OldBlobBytes returns the retained previous private area as raw bytes.
func (s *SealedObject) OldBlobBytes() []byte {
	if s == nil {
		return nil
	}
	return cloneSealedBytes(s.OldBlob.Buffer)
}

// PublicBytes returns the raw public area.
func (s *SealedObject) PublicBytes() []byte {
	if s == nil {
		return nil
	}
	return cloneSealedBytes(s.Public.Bytes())
}

// PrivateBytes returns the raw private area.
func (s *SealedObject) PrivateBytes() []byte {
	if s == nil {
		return nil
	}
	return cloneSealedBytes(s.Private.Buffer)
}

// AddCandidate appends a recovery candidate to the transaction.
func (s *SealedObject) AddCandidate(parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName) error {
	if s == nil {
		return ErrSealedObject
	}
	if err := s.normalize(); err != nil {
		return err
	}
	candidate := SealedCandidate{
		Parent:  parent,
		Public:  cloneSealedPublic(public),
		Private: cloneSealedPrivate(private),
		Name:    cloneSealedName(name),
	}
	if err := candidate.normalize(s); err != nil {
		return err
	}
	s.Candidates = append(s.Candidates, candidate)
	return nil
}

// WithCandidate returns a copy of the transaction with an additional recovery
// candidate.
func (s *SealedObject) WithCandidate(parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName) (*SealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	if err := txn.AddCandidate(parent, public, private, name); err != nil {
		return nil, err
	}
	return txn, nil
}

// Unseal returns the plaintext of a loaded sealed object. The returned data is
// checked against the transaction plaintext; a mismatch returns an error and
// flushes the handle so it cannot be reused for the wrong object.
func (o *LoadedSealedObject) Unseal(t transport.TPM, sessions ...Session) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	auth := PasswordAuth(cloneSealedBytes(o.Auth))
	var extra []Session
	if len(sessions) != 0 {
		// The first supplied session authorizes the sealed object; any
		// remaining sessions are extra sessions (for encryption, audit, etc.).
		auth = sessions[0]
		extra = sessions[1:]
	} else if o.Session != nil {
		auth = o.Session
	}
	return o.unsealWithSession(t, auth, extra...)
}

// UnsealWithPassword uses the transaction password for authorization and
// treats every supplied session as an extra session (for example, parameter
// encryption).
func (o *LoadedSealedObject) UnsealWithPassword(t transport.TPM, sessions ...Session) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	return o.unsealWithSession(t, PasswordAuth(cloneSealedBytes(o.Auth)), sessions...)
}

// UnsealWithAuth overrides the loaded object's authorization value for this
// attempt.
func (o *LoadedSealedObject) UnsealWithAuth(t transport.TPM, auth []byte, sessions ...Session) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	return o.unsealWithSession(t, PasswordAuth(cloneSealedBytes(auth)), sessions...)
}

// UnsealWithSession uses session to authorize the loaded sealed object.
func (o *LoadedSealedObject) UnsealWithSession(t transport.TPM, session Session, sessions ...Session) ([]byte, error) {
	if o == nil || o.Handle == 0 {
		return nil, ErrSealedObject
	}
	return o.unsealWithSession(t, session, sessions...)
}

// UnsealWithPolicy is an alias for UnsealWithSession.
func (o *LoadedSealedObject) UnsealWithPolicy(t transport.TPM, policy Session, sessions ...Session) ([]byte, error) {
	return o.UnsealWithSession(t, policy, sessions...)
}

func (o *LoadedSealedObject) unsealWithSession(t transport.TPM, auth Session, sessions ...Session) ([]byte, error) {
	item := AuthHandle{
		Handle: o.Handle,
		Name:   cloneSealedName(o.Name),
		Auth:   auth,
	}
	rsp, err := Unseal{ItemHandle: item}.Execute(t, sessions...)
	if err != nil {
		return nil, fmt.Errorf("%w: unsealing loaded object: %w", ErrSealedObject, err)
	}
	if !bytes.Equal(rsp.OutData.Buffer, o.Plaintext) {
		handle := o.Handle
		mismatch := fmt.Errorf(
			"%w: unsealed %x, transaction plaintext %x",
			ErrSealedObjectPlaintext, rsp.OutData.Buffer, o.Plaintext)
		if flushErr := o.Flush(t); flushErr != nil {
			return nil, fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, handle, flushErr)
		}
		return nil, mismatch
	}
	return cloneSealedBytes(rsp.OutData.Buffer), nil
}

// Flush flushes the loaded handle. It is safe to call on a nil loaded object
// or after the handle was already flushed.
func (o *LoadedSealedObject) Flush(t transport.TPM, sessions ...Session) error {
	if o == nil || o.Handle == 0 {
		return nil
	}
	handle := o.Handle
	if _, err := (FlushContext{FlushHandle: handle}).Execute(t); err != nil {
		return fmt.Errorf("%w: flushing loaded object: %v", ErrSealedObject, err)
	}
	o.Handle = 0
	o.ObjectHandle = 0
	return nil
}

// LoadFirstSealedObject tries each transaction in order and returns the first
// object that loads successfully. A failed attempt is discarded in full
// before the next candidate is tried; it never contributes its parent, Name,
// or public/private areas to the result.
func LoadFirstSealedObject(t transport.TPM, objects []*SealedObject, sessions ...Session) (*LoadedSealedObject, error) {
	if len(objects) == 0 {
		return nil, ErrNoSealedObjects
	}
	var errs []error
	for i, object := range objects {
		if object == nil {
			errs = append(errs, fmt.Errorf("sealed object %d: %w", i, ErrSealedObject))
			continue
		}
		loaded, err := object.Load(t, sessions...)
		if err == nil {
			return loaded, nil
		}
		errs = append(errs, fmt.Errorf("sealed object %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all sealed objects failed: %w", ErrSealedObject, errors.Join(errs...))
}

// LoadFirstSealedBlob is an alias for LoadFirstSealedObject.
func LoadFirstSealedBlob(t transport.TPM, objects []*SealedBlob, sessions ...Session) (*LoadedSealedObject, error) {
	return LoadFirstSealedObject(t, objects, sessions...)
}

// UnsealFirstSealedObject tries each transaction in order and returns the
// plaintext of the first one that loads and unseals its own committed
// plaintext.
func UnsealFirstSealedObject(t transport.TPM, objects []*SealedObject, sessions ...Session) ([]byte, error) {
	if len(objects) == 0 {
		return nil, ErrNoSealedObjects
	}
	var errs []error
	for i, object := range objects {
		if object == nil {
			errs = append(errs, fmt.Errorf("sealed object %d: %w", i, ErrSealedObject))
			continue
		}
		data, err := object.Unseal(t, sessions...)
		if err == nil {
			return data, nil
		}
		errs = append(errs, fmt.Errorf("sealed object %d: %w", i, err))
	}
	return nil, fmt.Errorf("%w: all sealed objects failed: %w", ErrSealedObject, errors.Join(errs...))
}

// UnsealFirstSealedBlob is an alias for UnsealFirstSealedObject.
func UnsealFirstSealedBlob(t transport.TPM, objects []*SealedBlob, sessions ...Session) ([]byte, error) {
	return UnsealFirstSealedObject(t, objects, sessions...)
}

// LoadFirstSealedObjectAndUnseal is an alias for UnsealFirstSealedObject.
func LoadFirstSealedObjectAndUnseal(t transport.TPM, objects []*SealedObject, sessions ...Session) ([]byte, error) {
	return UnsealFirstSealedObject(t, objects, sessions...)
}

// LoadSealedObject constructs a transaction and loads it in one step.
func LoadSealedObject(t transport.TPM, parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName, plaintext, auth []byte, policy ...[]byte) (*LoadedSealedObject, error) {
	sealed, err := NewSealedObjectFromPublic(parent, public, private, name, plaintext, auth, policy...)
	if err != nil {
		return nil, err
	}
	return sealed.Load(t)
}

// UnsealSealedObject constructs a transaction and unseals it in one step.
func UnsealSealedObject(t transport.TPM, parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName, plaintext, auth []byte, policy ...[]byte) ([]byte, error) {
	sealed, err := NewSealedObjectFromPublic(parent, public, private, name, plaintext, auth, policy...)
	if err != nil {
		return nil, err
	}
	return sealed.Unseal(t)
}

// LoadSealedBlob is an alias for LoadSealedObject.
func LoadSealedBlob(t transport.TPM, parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName, plaintext, auth []byte, policy ...[]byte) (*LoadedSealedObject, error) {
	return LoadSealedObject(t, parent, public, private, name, plaintext, auth, policy...)
}

// UnsealSealedBlob is an alias for UnsealSealedObject.
func UnsealSealedBlob(t transport.TPM, parent SealedParent, public TPM2BPublic, private TPM2BPrivate, name TPM2BName, plaintext, auth []byte, policy ...[]byte) ([]byte, error) {
	return UnsealSealedObject(t, parent, public, private, name, plaintext, auth, policy...)
}

func (s *SealedObject) loadCandidate(t transport.TPM, candidate SealedCandidate, sessions ...Session) (*LoadedSealedObject, error) {
	txn, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	candidate, err = candidate.normalized(txn)
	if err != nil {
		return nil, err
	}
	if len(candidate.Private.Buffer) == 0 {
		return nil, ErrSealedObjectPrivate
	}
	expected, err := sealedPublicName(candidate.Public)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealedObjectPublic, err)
	}
	if len(txn.Name.Buffer) != 0 && !bytes.Equal(txn.Name.Buffer, expected.Buffer) {
		return nil, fmt.Errorf(
			"%w: transaction Name %x, candidate public area Name %x",
			ErrSealedObjectMismatch, txn.Name.Buffer, expected.Buffer)
	}
	if len(candidate.Name.Buffer) != 0 && !bytes.Equal(candidate.Name.Buffer, expected.Buffer) {
		return nil, fmt.Errorf(
			"%w: candidate Name %x, public area Name %x",
			ErrSealedObjectMismatch, candidate.Name.Buffer, expected.Buffer)
	}

	parent, err := candidateParent(candidate.Parent, txn)
	if err != nil {
		return nil, err
	}
	loadRsp, err := Load{
		ParentHandle: parent,
		InPrivate:    cloneSealedPrivate(candidate.Private),
		InPublic:     cloneSealedPublic(candidate.Public),
	}.Execute(t, sessions...)
	if err != nil {
		if errors.Is(err, ErrObjectNameMismatch) {
			return nil, fmt.Errorf("%w: %w", ErrSealedObjectMismatch, err)
		}
		return nil, fmt.Errorf("%w: loading sealed object: %w", ErrSealedObject, err)
	}
	if !bytes.Equal(loadRsp.Name.Buffer, expected.Buffer) {
		mismatch := fmt.Errorf(
			"%w: loaded Name %x, transaction Name %x",
			ErrSealedObjectMismatch, loadRsp.Name.Buffer, expected.Buffer)
		if flushErr := flushContext(t, loadRsp.ObjectHandle); flushErr != nil {
			return nil, fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, loadRsp.ObjectHandle, flushErr)
		}
		return nil, mismatch
	}

	return &LoadedSealedObject{
		Handle:       loadRsp.ObjectHandle,
		ObjectHandle: loadRsp.ObjectHandle,
		Name:         cloneSealedName(expected),
		ObjectName:   cloneSealedName(expected),
		Public:       cloneSealedPublic(candidate.Public),
		Private:      cloneSealedPrivate(candidate.Private),
		Parent:       candidate.Parent,
		Plaintext:    cloneSealedBytes(txn.Plaintext),
		Data:         cloneSealedBytes(txn.Plaintext),
		Auth:         cloneSealedBytes(txn.Auth),
		Policy:       cloneSealedDigest(txn.Policy),
		Session:      txn.Session,
		PolicySession: txn.Session,
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
		Parent:           s.Parent,
		ParentName:       cloneSealedName(s.ParentName),
		ParentAuth:       cloneSealedBytes(s.ParentAuth),
		Public:           cloneSealedPublic(s.Public),
		Private:          cloneSealedPrivate(s.Private),
		Name:             cloneSealedName(s.Name),
		Plaintext:        cloneSealedBytes(s.Plaintext),
		Auth:             cloneSealedBytes(s.Auth),
		Policy:           cloneSealedDigest(s.Policy),
		Session:          s.Session,
		Primary:          s.Primary,
		ParentHandle:     s.ParentHandle,
		Key:              s.Key,
		PrimaryKey:       s.PrimaryKey,
		ParentKey:        s.ParentKey,
		ParentPassword:   cloneSealedBytes(s.ParentPassword),
		ParentHandleName: cloneSealedName(s.ParentHandleName),
		InPublic:         cloneSealedPublic(s.InPublic),
		OutPublic:        cloneSealedPublic(s.OutPublic),
		SealedPublic:     cloneSealedPublic(s.SealedPublic),
		InPrivate:        cloneSealedPrivate(s.InPrivate),
		OutPrivate:       cloneSealedPrivate(s.OutPrivate),
		SealedPrivate:    cloneSealedPrivate(s.SealedPrivate),
		ObjectName:       cloneSealedName(s.ObjectName),
		Data:             cloneSealedBytes(s.Data),
		Secret:           cloneSealedBytes(s.Secret),
		PlainText:        cloneSealedBytes(s.PlainText),
		Password:         cloneSealedBytes(s.Password),
		ObjectAuth:       cloneSealedBytes(s.ObjectAuth),
		ObjectPassword:   cloneSealedBytes(s.ObjectPassword),
		PCRPolicy:        cloneSealedDigest(s.PCRPolicy),
		AuthPolicy:       cloneSealedDigest(s.AuthPolicy),
		PolicySession:    s.PolicySession,
		OldPublic:        cloneSealedPublic(s.OldPublic),
		OldBlob:          cloneSealedPrivate(s.OldBlob),
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
	if s.Parent == nil {
		s.Parent = s.Primary
	}
	if s.Parent == nil {
		s.Parent = s.ParentHandle
	}
	if s.Parent == nil {
		s.Parent = s.Key
	}
	if s.Parent == nil {
		s.Parent = s.PrimaryKey
	}
	if s.Parent == nil {
		s.Parent = s.ParentKey
	}
	if s.Primary == nil {
		s.Primary = s.Parent
	}
	if s.ParentHandle == nil {
		s.ParentHandle = s.Parent
	}
	s.ParentName = firstSealedName(s.ParentName, s.ParentHandleName)
	if len(s.ParentName.Buffer) == 0 && s.Parent != nil {
		if known := s.Parent.KnownName(); known != nil {
			s.ParentName = cloneSealedName(*known)
		}
	}
	s.ParentAuth = firstSealedBytes(s.ParentAuth, s.ParentPassword)

	s.Public = firstSealedPublic(s.Public, s.InPublic, s.OutPublic, s.SealedPublic, s.OldPublic)
	s.Private = firstSealedPrivate(s.Private, s.InPrivate, s.OutPrivate, s.SealedPrivate, s.OldBlob)
	if len(s.OldPublic.Bytes()) == 0 {
		s.OldPublic = cloneSealedPublic(s.Public)
	}
	if len(s.OldBlob.Buffer) == 0 {
		s.OldBlob = cloneSealedPrivate(s.Private)
	}
	s.Name = firstSealedName(s.Name, s.ObjectName)
	s.Plaintext = firstSealedBytes(s.Plaintext, s.Data, s.Secret, s.PlainText)
	s.Auth = firstSealedBytes(s.Auth, s.Password, s.ObjectAuth, s.ObjectPassword)
	s.Policy = firstSealedDigest(s.Policy, s.PCRPolicy, s.AuthPolicy)
	if s.Session == nil {
		s.Session = s.PolicySession
	}
	s.PolicySession = s.Session

	// Mirror the canonical values back into the compatibility fields so
	// callers can inspect whichever spelling they prefer.
	s.Primary = s.Parent
	s.ParentHandle = s.Parent
	s.Key = s.Parent
	s.PrimaryKey = s.Parent
	s.ParentKey = s.Parent
	s.ParentPassword = cloneSealedBytes(s.ParentAuth)
	s.ParentHandleName = cloneSealedName(s.ParentName)
	s.InPublic = cloneSealedPublic(s.Public)
	s.OutPublic = cloneSealedPublic(s.Public)
	s.SealedPublic = cloneSealedPublic(s.Public)
	s.InPrivate = cloneSealedPrivate(s.Private)
	s.OutPrivate = cloneSealedPrivate(s.Private)
	s.SealedPrivate = cloneSealedPrivate(s.Private)
	s.ObjectName = cloneSealedName(s.Name)
	s.Data = cloneSealedBytes(s.Plaintext)
	s.Secret = cloneSealedBytes(s.Plaintext)
	s.PlainText = cloneSealedBytes(s.Plaintext)
	s.Password = cloneSealedBytes(s.Auth)
	s.ObjectAuth = cloneSealedBytes(s.Auth)
	s.ObjectPassword = cloneSealedBytes(s.Auth)
	s.PCRPolicy = cloneSealedDigest(s.Policy)
	s.AuthPolicy = cloneSealedDigest(s.Policy)

	if _, err := s.parentHandle(); err != nil {
		return err
	}
	if len(s.Public.Bytes()) == 0 {
		return ErrSealedObjectPublic
	}
	name, err := sealedPublicName(s.Public)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSealedObjectPublic, err)
	}
	if len(s.Name.Buffer) == 0 {
		s.Name = name
		s.ObjectName = cloneSealedName(name)
	} else if !bytes.Equal(s.Name.Buffer, name.Buffer) {
		return fmt.Errorf("%w: supplied %x, public area %x", ErrSealedObjectName, s.Name.Buffer, name.Buffer)
	}
	if len(s.Policy.Buffer) == 0 {
		if contents, err := Unmarshal[TPMTPublic](s.Public.Bytes()); err == nil {
			s.Policy = cloneSealedDigest(contents.AuthPolicy)
			s.PCRPolicy = cloneSealedDigest(s.Policy)
			s.AuthPolicy = cloneSealedDigest(s.Policy)
		}
	}
	for i := range s.Candidates {
		if err := s.Candidates[i].normalize(s); err != nil {
			return fmt.Errorf("candidate %d: %w", i, err)
		}
	}
	return nil
}

func (s *SealedObject) recoveryCandidates() []SealedCandidate {
	primary := SealedCandidate{
		Parent:  s.Parent,
		Public:  cloneSealedPublic(s.Public),
		Private: cloneSealedPrivate(s.Private),
		Name:    cloneSealedName(s.Name),
	}
	result := []SealedCandidate{primary}
	if len(s.OldBlob.Buffer) != 0 && !bytes.Equal(s.OldBlob.Buffer, s.Private.Buffer) {
		oldPublic := s.OldPublic
		if len(oldPublic.Bytes()) == 0 {
			oldPublic = cloneSealedPublic(s.Public)
		}
		result = append(result, SealedCandidate{
			Parent:  s.Parent,
			Public:  cloneSealedPublic(oldPublic),
			Private: cloneSealedPrivate(s.OldBlob),
		})
	}
	for _, candidate := range s.Candidates {
		result = append(result, candidate.clone())
	}
	return result
}

func (s *SealedObject) parentHandle() (handle, error) {
	return candidateParent(s.Parent, s)
}

func (s *SealedObject) setParent(parent SealedParent) {
	if parent == nil {
		return
	}
	if s.Parent == nil {
		s.Parent = parent
		return
	}
	if s.Primary == nil {
		s.Primary = parent
	}
}

func replaceSealedParent(s *SealedObject, parent SealedParent) {
	s.Parent = parent
	s.Primary = parent
	s.ParentHandle = parent
	s.ParentName = TPM2BName{}
	s.ParentHandleName = TPM2BName{}
	if parent != nil {
		if known := parent.KnownName(); known != nil {
			s.ParentName = cloneSealedName(*known)
			s.ParentHandleName = cloneSealedName(*known)
		}
	}
	switch parent.(type) {
	case AuthHandle, *AuthHandle, NamedHandle, *NamedHandle:
		// These handles carry their own authorization state. Do not reuse the
		// previous parent's password for a different parent.
		s.ParentAuth = nil
		s.ParentPassword = nil
	}
}

func candidateParent(parent SealedParent, txn *SealedObject) (handle, error) {
	if parent == nil {
		return nil, ErrSealedObjectParent
	}
	value := TPMHandle(parent.HandleValue())
	if value == 0 || value == invalidHandleValue {
		return nil, fmt.Errorf("%w: invalid handle %#x", ErrSealedObjectParent, value)
	}

	name := parent.KnownName()
	if (name == nil || len(name.Buffer) == 0) && len(txn.ParentName.Buffer) != 0 {
		name = &txn.ParentName
	}

	switch p := parent.(type) {
	case AuthHandle:
		if len(p.Name.Buffer) == 0 && name != nil {
			p.Name = cloneSealedName(*name)
		}
		if p.Auth == nil {
			p.Auth = PasswordAuth(cloneSealedBytes(txn.ParentAuth))
		}
		if len(p.Name.Buffer) == 0 {
			return nil, fmt.Errorf("%w: parent %#x has no Name", ErrSealedObjectParent, value)
		}
		return p, nil
	case *AuthHandle:
		if p == nil {
			return nil, ErrSealedObjectParent
		}
		authHandle := *p
		if len(authHandle.Name.Buffer) == 0 && name != nil {
			authHandle.Name = cloneSealedName(*name)
		}
		if authHandle.Auth == nil {
			authHandle.Auth = PasswordAuth(cloneSealedBytes(txn.ParentAuth))
		}
		if len(authHandle.Name.Buffer) == 0 {
			return nil, fmt.Errorf("%w: parent %#x has no Name", ErrSealedObjectParent, value)
		}
		return authHandle, nil
	case NamedHandle:
		if len(p.Name.Buffer) == 0 && name != nil {
			p.Name = cloneSealedName(*name)
		}
		if len(p.Name.Buffer) == 0 {
			return nil, fmt.Errorf("%w: parent %#x has no Name", ErrSealedObjectParent, value)
		}
		if txn.ParentAuth != nil {
			return AuthHandle{
				Handle: p.Handle,
				Name:   cloneSealedName(p.Name),
				Auth:   PasswordAuth(cloneSealedBytes(txn.ParentAuth)),
			}, nil
		}
		return p, nil
	case *NamedHandle:
		if p == nil {
			return nil, ErrSealedObjectParent
		}
		namedHandle := *p
		if len(namedHandle.Name.Buffer) == 0 && name != nil {
			namedHandle.Name = cloneSealedName(*name)
		}
		if len(namedHandle.Name.Buffer) == 0 {
			return nil, fmt.Errorf("%w: parent %#x has no Name", ErrSealedObjectParent, value)
		}
		if txn.ParentAuth != nil {
			return AuthHandle{
				Handle: namedHandle.Handle,
				Name:   cloneSealedName(namedHandle.Name),
				Auth:   PasswordAuth(cloneSealedBytes(txn.ParentAuth)),
			}, nil
		}
		return namedHandle, nil
	default:
		if name == nil || len(name.Buffer) == 0 {
			if txn.ParentAuth != nil {
				return nil, fmt.Errorf("%w: parent %#x has no Name", ErrSealedObjectParent, value)
			}
			return parent, nil
		}
		if txn.ParentAuth != nil {
			return AuthHandle{
				Handle: value,
				Name:   cloneSealedName(*name),
				Auth:   PasswordAuth(cloneSealedBytes(txn.ParentAuth)),
			}, nil
		}
		return NamedHandle{Handle: value, Name: cloneSealedName(*name)}, nil
	}
}

func (c SealedCandidate) normalized(txn *SealedObject) (SealedCandidate, error) {
	candidate := c.clone()
	if candidate.Parent == nil {
		candidate.Parent = txn.Parent
	}
	if candidate.Primary == nil {
		candidate.Primary = candidate.Parent
	}
	if candidate.Parent == nil {
		candidate.Parent = candidate.Primary
	}
	candidate.Public = firstSealedPublic(candidate.Public, candidate.InPublic, txn.Public)
	candidate.Private = firstSealedPrivate(candidate.Private, candidate.InPrivate, txn.Private)
	candidate.Name = firstSealedName(candidate.Name, candidate.ObjectName, txn.Name)
	if candidate.Plaintext != nil && !bytes.Equal(candidate.Plaintext, txn.Plaintext) {
		return SealedCandidate{}, fmt.Errorf("%w: candidate plaintext does not match transaction", ErrSealedObjectPlaintext)
	}
	if candidate.Auth != nil && !bytes.Equal(candidate.Auth, txn.Auth) {
		return SealedCandidate{}, fmt.Errorf("%w: candidate auth does not match transaction", ErrSealedObjectMismatch)
	}
	if len(candidate.Policy.Buffer) != 0 && !bytes.Equal(candidate.Policy.Buffer, txn.Policy.Buffer) {
		return SealedCandidate{}, fmt.Errorf("%w: candidate policy does not match transaction", ErrSealedObjectMismatch)
	}
	if candidate.Parent == nil {
		return SealedCandidate{}, ErrSealedObjectParent
	}
	if len(candidate.Public.Bytes()) == 0 {
		return SealedCandidate{}, ErrSealedObjectPublic
	}
	if len(candidate.Private.Buffer) == 0 {
		return SealedCandidate{}, ErrSealedObjectPrivate
	}
	return candidate, nil
}

func (c SealedCandidate) clone() SealedCandidate {
	return SealedCandidate{
		Parent:     c.Parent,
		Public:     cloneSealedPublic(c.Public),
		Private:    cloneSealedPrivate(c.Private),
		Name:       cloneSealedName(c.Name),
		Plaintext:  cloneSealedBytes(c.Plaintext),
		Auth:       cloneSealedBytes(c.Auth),
		Policy:     cloneSealedDigest(c.Policy),
		Primary:    c.Primary,
		InPublic:   cloneSealedPublic(c.InPublic),
		InPrivate:  cloneSealedPrivate(c.InPrivate),
		ObjectName: cloneSealedName(c.ObjectName),
	}
}

func (c *SealedCandidate) normalize(txn *SealedObject) error {
	normalized, err := c.normalized(txn)
	if err != nil {
		return err
	}
	*c = normalized
	return nil
}

func verifyLoadResponse(t transport.TPM, public TPM2BPublic, rsp *LoadResponse) error {
	if rsp == nil {
		return nil
	}
	publicBytes := public.Bytes()
	contents, err := Unmarshal[TPMTPublic](publicBytes)
	if err != nil {
		// Preserve the previous behavior for opaque public areas. The TPM is
		// still responsible for validating the marshalled public area.
		return nil
	}
	if !bytes.Equal(Marshal(contents), publicBytes) {
		// The caller supplied a non-canonical encoding (for example, a
		// template that the TPM will normalize). Do not reject it here.
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
		"%w: loaded Name %x, public area Name %x",
		ErrObjectNameMismatch, rsp.Name.Buffer, expected.Buffer)
	if err := flushContext(t, rsp.ObjectHandle); err != nil {
		return fmt.Errorf("%w (also failed to flush %#x: %v)", mismatch, rsp.ObjectHandle, err)
	}
	return mismatch
}

func sealedPublicName(public TPM2BPublic) (TPM2BName, error) {
	contents, err := Unmarshal[TPMTPublic](public.Bytes())
	if err != nil {
		return TPM2BName{}, fmt.Errorf("parsing sealed public area: %w", err)
	}
	name, err := ObjectName(contents)
	if err != nil {
		return TPM2BName{}, fmt.Errorf("computing sealed object Name: %w", err)
	}
	return *name, nil
}

func flushContext(t transport.TPM, h TPMHandle) error {
	_, err := FlushContext{FlushHandle: h}.Execute(t)
	if err != nil {
		return err
	}
	return nil
}

func firstSealedPublic(values ...TPM2BPublic) TPM2BPublic {
	for _, value := range values {
		if len(value.Bytes()) != 0 {
			return cloneSealedPublic(value)
		}
	}
	return TPM2BPublic{}
}

func firstSealedPrivate(values ...TPM2BPrivate) TPM2BPrivate {
	for _, value := range values {
		if len(value.Buffer) != 0 {
			return cloneSealedPrivate(value)
		}
	}
	return TPM2BPrivate{}
}

func firstSealedName(values ...TPM2BName) TPM2BName {
	for _, value := range values {
		if len(value.Buffer) != 0 {
			return cloneSealedName(value)
		}
	}
	return TPM2BName{}
}

func firstSealedDigest(values ...TPM2BDigest) TPM2BDigest {
	for _, value := range values {
		if len(value.Buffer) != 0 {
			return cloneSealedDigest(value)
		}
	}
	return TPM2BDigest{}
}

func firstSealedBytes(values ...[]byte) []byte {
	for _, value := range values {
		if value != nil {
			return cloneSealedBytes(value)
		}
	}
	return nil
}

func cloneSealedPublic(value TPM2BPublic) TPM2BPublic {
	return BytesAs2B[TPMTPublic](cloneSealedBytes(value.Bytes()))
}

func cloneSealedPrivate(value TPM2BPrivate) TPM2BPrivate {
	return TPM2BPrivate{Buffer: cloneSealedBytes(value.Buffer)}
}

func cloneSealedName(value TPM2BName) TPM2BName {
	return TPM2BName{Buffer: cloneSealedBytes(value.Buffer)}
}

func cloneSealedDigest(value TPM2BDigest) TPM2BDigest {
	return TPM2BDigest{Buffer: cloneSealedBytes(value.Buffer)}
}

func cloneSealedBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}
