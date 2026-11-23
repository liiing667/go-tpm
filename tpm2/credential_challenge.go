package tpm2

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

const (
	credentialChallengeVersion = 1
	credentialMaxDigestSize    = 64
)

var (
	// ErrCredentialChallenge is the base error for credential challenge
	// failures. Callers should use errors.Is with this value or one of the
	// more specific values below.
	ErrCredentialChallenge = errors.New("tpm2: credential challenge")
	// ErrCredentialChallengeIdentity means that the supplied EK or AK does
	// not identify the object for which the challenge was created.
	ErrCredentialChallengeIdentity = fmt.Errorf("%w: EK or AK identity mismatch", ErrCredentialChallenge)
	// ErrCredentialChallengeConsumed means that the challenge has already
	// produced a successful activation result.
	ErrCredentialChallengeConsumed = fmt.Errorf("%w: challenge already consumed", ErrCredentialChallenge)
	// ErrCredentialChallengeState means that the challenge can no longer be
	// used because a previous attempt permanently failed.
	ErrCredentialChallengeState = fmt.Errorf("%w: challenge is no longer usable", ErrCredentialChallenge)
	// ErrCredentialChallengeName means that an AK Name is not a valid TPM
	// object Name.
	ErrCredentialChallengeName = fmt.Errorf("%w: invalid AK Name", ErrCredentialChallenge)
	// ErrCredentialChallengeBlob means that a credential blob is empty or is
	// not a well-formed TPMS_ID_OBJECT.
	ErrCredentialChallengeBlob = fmt.Errorf("%w: invalid credential blob", ErrCredentialChallenge)
	// ErrCredentialChallengeSecret means that an encrypted secret is empty.
	ErrCredentialChallengeSecret = fmt.Errorf("%w: invalid encrypted secret", ErrCredentialChallenge)
	// ErrCredentialChallengeCredential means that the credential value cannot
	// be represented by a TPM2B_DIGEST.
	ErrCredentialChallengeCredential = fmt.Errorf("%w: invalid credential value", ErrCredentialChallenge)
	// ErrCredentialChallengeResult means that the TPM returned a credential
	// value other than the one committed to by the challenge.
	ErrCredentialChallengeResult = fmt.Errorf("%w: activation result mismatch", ErrCredentialChallenge)
	// ErrCredentialChallengeSnapshot means that a serialized challenge is
	// malformed, was modified, or belongs to another challenge.
	ErrCredentialChallengeSnapshot = fmt.Errorf("%w: invalid challenge snapshot", ErrCredentialChallenge)
)

// CredentialChallengeState is the lifecycle of a CredentialChallenge.
type CredentialChallengeState uint8

const (
	// CredentialChallengeReady means the challenge may be activated with
	// the EK and AK that it committed to.
	CredentialChallengeReady CredentialChallengeState = iota
	// CredentialChallengeActivated means the challenge produced its
	// credential value and can no longer be consumed.
	CredentialChallengeActivated
	// CredentialChallengeFailed means the challenge permanently failed,
	// for example because the TPM returned a different credential value.
	CredentialChallengeFailed
)

// Aliases make the lifecycle names readable in callers that use a
// Challenge-prefixed vocabulary or the Succeeded spelling.
const (
	// ChallengeReady is an alias for CredentialChallengeReady.
	ChallengeReady = CredentialChallengeReady
	// ChallengeActivated is an alias for CredentialChallengeActivated.
	ChallengeActivated = CredentialChallengeActivated
	// CredentialChallengeSucceeded is an alias for
	// CredentialChallengeActivated.
	CredentialChallengeSucceeded = CredentialChallengeActivated
	// ChallengeSucceeded is an alias for CredentialChallengeActivated.
	ChallengeSucceeded = CredentialChallengeActivated
	// ChallengeFailed is an alias for CredentialChallengeFailed.
	ChallengeFailed = CredentialChallengeFailed
)

// String implements fmt.Stringer.
func (s CredentialChallengeState) String() string {
	switch s {
	case CredentialChallengeReady:
		return "ready"
	case CredentialChallengeActivated:
		return "activated"
	case CredentialChallengeFailed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// CredentialChallengeIdentity identifies every value that takes part in a
// credential challenge. The EK public area is represented both by its TPM Name
// and by a digest of its canonical TPM encoding. Credential material is
// represented by digests so the identity can be logged without disclosing the
// credential, credential blob, or encrypted secret.
type CredentialChallengeIdentity struct {
	ChallengeID      [32]byte
	EKName           TPM2BName
	EKPublicDigest   [32]byte
	AKName           TPM2BName
	CredentialDigest [32]byte
	BlobDigest       [32]byte
	SecretDigest     [32]byte
}

// CredentialChallengeAttempt is the auditable record of one activation
// attempt. It deliberately contains digests rather than credential material.
type CredentialChallengeAttempt struct {
	Stage            string
	EKName           TPM2BName
	AKName           TPM2BName
	EKPublicDigest   [32]byte
	CredentialDigest [32]byte
	BlobDigest       [32]byte
	SecretDigest     [32]byte
	Err              error
}

// CredentialChallengeAttemptSnapshot is the serializable form of an
// activation attempt. The error is stored as text so a snapshot can preserve
// failure evidence across a restart.
type CredentialChallengeAttemptSnapshot struct {
	Stage            string
	EKName           []byte
	AKName           []byte
	EKPublicDigest   [32]byte
	CredentialDigest [32]byte
	BlobDigest       [32]byte
	SecretDigest     [32]byte
	Error            string
}

// CredentialChallengeResult is returned after a successful activation. It
// embeds ActivateCredentialResponse so existing code can continue to read
// result.CertInfo.
type CredentialChallengeResult struct {
	ActivateCredentialResponse
	Identity CredentialChallengeIdentity
	State    CredentialChallengeState
}

// CredentialChallengeReport is a log-safe view of a challenge.
type CredentialChallengeReport struct {
	Identity CredentialChallengeIdentity
	State    CredentialChallengeState
	Attempts []CredentialChallengeAttempt
	Err      error
}

// CredentialChallengeError describes a failed activation and preserves the
// challenge identity and failure stage without retaining any secret material.
type CredentialChallengeError struct {
	Stage    string
	Identity CredentialChallengeIdentity
	Kind     error
	Err      error
}

// Error implements error.
func (e *CredentialChallengeError) Error() string {
	if e == nil {
		return ErrCredentialChallenge.Error()
	}
	detail := ""
	if e.Kind != nil {
		detail = e.Kind.Error() + ": "
	}
	if e.Err != nil {
		detail += e.Err.Error()
	} else {
		detail += "activation rejected"
	}
	return fmt.Sprintf("%s at %s (EK %x, AK %x, credential %x)",
		detail, e.Stage, e.Identity.EKName.Buffer, e.Identity.AKName.Buffer,
		e.Identity.CredentialDigest)
}

// Unwrap exposes both the specific challenge error and the underlying TPM or
// validation error to errors.Is and errors.As.
func (e *CredentialChallengeError) Unwrap() []error {
	if e == nil {
		return []error{ErrCredentialChallenge}
	}
	result := make([]error, 0, 2)
	if e.Kind != nil {
		result = append(result, e.Kind)
	}
	if e.Err != nil {
		result = append(result, e.Err)
	}
	return result
}

// CredentialChallenge binds an EK public area, an AK Name, the credential
// value, the credential blob and the encrypted secret into one activation
// transaction. Activation always uses the blob, secret and credential
// committed to at construction time; callers cannot substitute a blob or
// secret from another challenge.
type CredentialChallenge struct {
	mu sync.Mutex

	id               [32]byte
	ekPublicBytes    []byte
	ekPublicDigest   [32]byte
	ekName           TPM2BName
	akName           TPM2BName
	credential       []byte
	credentialDigest [32]byte
	blob             TPM2BIDObject
	secret           TPM2BEncryptedSecret
	state            CredentialChallengeState
	attempts         []CredentialChallengeAttempt
	lastErr          error
	lastFailure      error
}

// Aliases for callers that use Challenge as the transaction name.
type (
	// Challenge is an alias for CredentialChallenge.
	Challenge = CredentialChallenge
	// ChallengeState is an alias for CredentialChallengeState.
	ChallengeState = CredentialChallengeState
	// ChallengeIdentity is an alias for CredentialChallengeIdentity.
	ChallengeIdentity = CredentialChallengeIdentity
	// ChallengeAttempt is an alias for CredentialChallengeAttempt.
	ChallengeAttempt = CredentialChallengeAttempt
	// ChallengeAttemptSnapshot is an alias for CredentialChallengeAttemptSnapshot.
	ChallengeAttemptSnapshot = CredentialChallengeAttemptSnapshot
	// ChallengeResult is an alias for CredentialChallengeResult.
	ChallengeResult = CredentialChallengeResult
	// ChallengeReport is an alias for CredentialChallengeReport.
	ChallengeReport = CredentialChallengeReport
	// ChallengeError is an alias for CredentialChallengeError.
	ChallengeError = CredentialChallengeError
	// ChallengeSnapshot is an alias for CredentialChallengeSnapshot.
	ChallengeSnapshot = CredentialChallengeSnapshot
)

// NewCredentialChallenge creates a credential challenge using the TPM
// MakeCredential algorithm in software. The EK public area and AK Name are
// committed to the challenge, and the returned secret can only be activated
// with that same identity.
func NewCredentialChallenge(random io.Reader, ekPublic *TPMTPublic, akName []byte, credential []byte) (*CredentialChallenge, error) {
	if random == nil {
		random = cryptorand.Reader
	}
	public, err := cloneCredentialPublic(ekPublic)
	if err != nil {
		return nil, err
	}
	name := TPM2BName{Buffer: cloneCredentialBytes(akName)}
	if err := validateCredentialAKName(name); err != nil {
		return nil, err
	}
	key, err := ImportEncapsulationKey(public)
	if err != nil {
		return nil, fmt.Errorf("importing EK public area: %w", err)
	}
	idObject, secret, err := CreateCredential(random, key, name.Buffer, credential)
	if err != nil {
		return nil, err
	}
	return newCredentialChallenge(public, name, credential, idObject, secret)
}

// NewChallenge is an alias for NewCredentialChallenge.
func NewChallenge(random io.Reader, ekPublic *TPMTPublic, akName []byte, credential []byte) (*CredentialChallenge, error) {
	return NewCredentialChallenge(random, ekPublic, akName, credential)
}

// CreateCredentialChallenge is an alias for NewCredentialChallenge.
func CreateCredentialChallenge(random io.Reader, ekPublic *TPMTPublic, akName []byte, credential []byte) (*CredentialChallenge, error) {
	return NewCredentialChallenge(random, ekPublic, akName, credential)
}

// NewCredentialChallengeFromPublic is NewCredentialChallenge for a TPM2B
// public area, including a legacy public area read from a TPM.
func NewCredentialChallengeFromPublic(random io.Reader, ekPublic TPM2BPublic, akName []byte, credential []byte) (*CredentialChallenge, error) {
	public, err := ekPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parsing EK public area: %w", err)
	}
	return NewCredentialChallenge(random, public, akName, credential)
}

// NewCredentialChallengeFromPublicBytes is NewCredentialChallenge for a raw
// TPMT_PUBLIC encoding, such as the contents of an EK certificate extension.
func NewCredentialChallengeFromPublicBytes(random io.Reader, ekPublic []byte, akName []byte, credential []byte) (*CredentialChallenge, error) {
	public, err := Unmarshal[TPMTPublic](ekPublic)
	if err != nil {
		return nil, fmt.Errorf("parsing EK public area: %w", err)
	}
	return NewCredentialChallenge(random, public, akName, credential)
}

// NewCredentialChallengeFromMakeCredential commits an existing
// TPM2_MakeCredential response to the challenge transaction.
func NewCredentialChallengeFromMakeCredential(ekPublic *TPMTPublic, akName []byte, credential []byte, rsp *MakeCredentialResponse) (*CredentialChallenge, error) {
	if rsp == nil {
		return nil, fmt.Errorf("%w: nil MakeCredential response", ErrCredentialChallenge)
	}
	return newCredentialChallengeFromParts(ekPublic, TPM2BName{Buffer: cloneCredentialBytes(akName)}, credential, rsp.CredentialBlob.Buffer, rsp.Secret.Buffer)
}

// NewCredentialChallengeFromTPMResponse is
// NewCredentialChallengeFromMakeCredential for a TPM2B public area.
func NewCredentialChallengeFromTPMResponse(ekPublic TPM2BPublic, akName []byte, credential []byte, rsp *MakeCredentialResponse) (*CredentialChallenge, error) {
	public, err := ekPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parsing EK public area: %w", err)
	}
	return NewCredentialChallengeFromMakeCredential(public, akName, credential, rsp)
}

// NewCredentialChallengeFromCredential commits an existing credential blob and
// encrypted secret to an EK public area and AK Name. The credential value is
// not accepted from the TPM response; the caller supplies the value it expects
// to be activated.
func NewCredentialChallengeFromCredential(ekPublic *TPMTPublic, akName []byte, credential []byte, credentialBlob []byte, secret []byte) (*CredentialChallenge, error) {
	return newCredentialChallengeFromParts(ekPublic, TPM2BName{Buffer: cloneCredentialBytes(akName)}, credential, credentialBlob, secret)
}

// NewCredentialChallengeFromName is NewCredentialChallenge with a structured
// AK Name.
func NewCredentialChallengeFromName(random io.Reader, ekPublic *TPMTPublic, akName TPM2BName, credential []byte) (*CredentialChallenge, error) {
	return NewCredentialChallenge(random, ekPublic, akName.Buffer, credential)
}

// MakeCredentialChallenge asks the TPM to make a credential for akName using
// the loaded EK, then commits the resulting EK public area, AK Name,
// credential blob and secret to a single challenge. The EK's public area is
// read from the TPM rather than trusted from the caller.
func MakeCredentialChallenge(t transport.TPM, ek handle, akName []byte, credential []byte) (*CredentialChallenge, error) {
	if t == nil {
		return nil, fmt.Errorf("%w: nil TPM transport", ErrCredentialChallenge)
	}
	if ek == nil {
		return nil, fmt.Errorf("%w: nil EK handle", ErrCredentialChallengeIdentity)
	}
	name := TPM2BName{Buffer: cloneCredentialBytes(akName)}
	if err := validateCredentialAKName(name); err != nil {
		return nil, err
	}
	public, err := ReadPublic{ObjectHandle: ek}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("reading EK public area: %w", err)
	}
	if known := ek.KnownName(); known != nil && len(known.Buffer) != 0 && !bytes.Equal(known.Buffer, public.Name.Buffer) {
		return nil, fmt.Errorf("%w: EK handle Name %x does not match TPM Name %x",
			ErrCredentialChallengeIdentity, known.Buffer, public.Name.Buffer)
	}
	outPublic, err := public.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parsing EK public area: %w", err)
	}
	rsp, err := MakeCredential{
		Handle:     TPMIDHObject(ek.HandleValue()),
		Credential: TPM2BDigest{Buffer: cloneCredentialBytes(credential)},
		ObjectName: name,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("making credential: %w", err)
	}
	return NewCredentialChallengeFromMakeCredential(outPublic, name.Buffer, credential, rsp)
}

// MakeCredentialChallengeFromName is MakeCredentialChallenge with a structured
// AK Name.
func MakeCredentialChallengeFromName(t transport.TPM, ek handle, akName TPM2BName, credential []byte) (*CredentialChallenge, error) {
	return MakeCredentialChallenge(t, ek, akName.Buffer, credential)
}

// MakeChallenge is an alias for MakeCredentialChallenge.
func MakeChallenge(t transport.TPM, ek handle, akName []byte, credential []byte) (*CredentialChallenge, error) {
	return MakeCredentialChallenge(t, ek, akName, credential)
}

func newCredentialChallengeFromParts(ekPublic *TPMTPublic, akName TPM2BName, credential, idObject, secret []byte) (*CredentialChallenge, error) {
	public, err := cloneCredentialPublic(ekPublic)
	if err != nil {
		return nil, err
	}
	if err := validateCredentialAKName(akName); err != nil {
		return nil, err
	}
	if len(idObject) == 0 {
		return nil, fmt.Errorf("%w: empty credential blob", ErrCredentialChallengeBlob)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: empty encrypted secret", ErrCredentialChallengeSecret)
	}
	blob := TPM2BIDObject{Buffer: cloneCredentialBytes(idObject)}
	if err := validateCredentialBlob(blob); err != nil {
		return nil, err
	}
	name, err := ObjectName(public)
	if err != nil {
		return nil, fmt.Errorf("computing EK Name: %w", err)
	}
	if err := validateCredentialBlobHash(blob, *name); err != nil {
		return nil, err
	}
	return newCredentialChallenge(public, akName, credential, idObject, secret)
}

func newCredentialChallenge(public *TPMTPublic, akName TPM2BName, credential, idObject, secret []byte) (result *CredentialChallenge, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("%w: malformed EK public area: %v", ErrCredentialChallenge, recovered)
		}
	}()
	publicBytes := Marshal(*public)
	ekName, err := ObjectName(public)
	if err != nil {
		return nil, fmt.Errorf("computing EK Name: %w", err)
	}
	if err := validateCredentialAKName(akName); err != nil {
		return nil, err
	}
	if len(credential) > 65535 {
		return nil, ErrCredentialChallengeCredential
	}
	blob := TPM2BIDObject{Buffer: cloneCredentialBytes(idObject)}
	if err := validateCredentialBlob(blob); err != nil {
		return nil, err
	}
	if err := validateCredentialBlobHash(blob, *ekName); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: empty encrypted secret", ErrCredentialChallengeSecret)
	}
	c := &CredentialChallenge{
		ekPublicBytes:    cloneCredentialBytes(publicBytes),
		ekPublicDigest:   sha256.Sum256(publicBytes),
		ekName:           cloneCredentialName(*ekName),
		akName:           cloneCredentialName(akName),
		credential:       cloneCredentialBytes(credential),
		credentialDigest: sha256.Sum256(credential),
		blob:             blob,
		secret:           TPM2BEncryptedSecret{Buffer: cloneCredentialBytes(secret)},
		state:            CredentialChallengeReady,
	}
	c.id = c.computeID()
	return c, nil
}

// Identity returns the immutable identity of the challenge.
func (c *CredentialChallenge) Identity() CredentialChallengeIdentity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identityLocked()
}

// ChallengeID returns the digest that identifies this challenge transaction.
func (c *CredentialChallenge) ChallengeID() [32]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

// ID is an alias for ChallengeID.
func (c *CredentialChallenge) ID() [32]byte {
	return c.ChallengeID()
}

// State returns the current lifecycle state.
func (c *CredentialChallenge) State() CredentialChallengeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Attempts returns a copy of the auditable activation attempts.
func (c *CredentialChallenge) Attempts() []CredentialChallengeAttempt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneCredentialAttempts(c.attempts)
}

// EKName returns the EK Name committed to by the challenge.
func (c *CredentialChallenge) EKName() TPM2BName {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneCredentialName(c.ekName)
}

// EKPublicBytes returns a copy of the canonical TPMT_PUBLIC encoding
// committed to by the challenge.
func (c *CredentialChallenge) EKPublicBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneCredentialBytes(c.ekPublicBytes)
}

// EKPublic returns the EK public area committed to by the challenge.
func (c *CredentialChallenge) EKPublic() TPM2BPublic {
	return BytesAs2B[TPMTPublic, *TPMTPublic](c.EKPublicBytes())
}

// AKName returns the AK Name committed to by the challenge.
func (c *CredentialChallenge) AKName() TPM2BName {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneCredentialName(c.akName)
}

// Credential returns a copy of the expected credential value.
func (c *CredentialChallenge) Credential() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneCredentialBytes(c.credential)
}

// CredentialBlob returns a copy of the credential blob committed to by the
// challenge.
func (c *CredentialChallenge) CredentialBlob() TPM2BIDObject {
	c.mu.Lock()
	defer c.mu.Unlock()
	return TPM2BIDObject{Buffer: cloneCredentialBytes(c.blob.Buffer)}
}

// Secret returns a copy of the encrypted secret committed to by the challenge.
func (c *CredentialChallenge) Secret() TPM2BEncryptedSecret {
	c.mu.Lock()
	defer c.mu.Unlock()
	return TPM2BEncryptedSecret{Buffer: cloneCredentialBytes(c.secret.Buffer)}
}

// VerifyEKPublic checks that public is the EK public area committed to by the
// challenge. It is useful when the public area comes from an EK certificate or
// another consumer that is separate from the TPM handle.
func (c *CredentialChallenge) VerifyEKPublic(public *TPMTPublic) error {
	clone, err := cloneCredentialPublic(public)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !bytes.Equal(Marshal(*clone), c.ekPublicBytes) {
		return fmt.Errorf("%w: EK public area does not match the challenge", ErrCredentialChallengeIdentity)
	}
	return nil
}

// VerifyAKName checks that name is the AK Name committed to by the challenge.
func (c *CredentialChallenge) VerifyAKName(name TPM2BName) error {
	if err := validateCredentialObjectName(name); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !bytes.Equal(name.Buffer, c.akName.Buffer) {
		return fmt.Errorf("%w: AK Name does not match the challenge", ErrCredentialChallengeIdentity)
	}
	return nil
}

// Activate activates the challenge using only the EK, AK, blob, secret and
// credential committed to by this challenge. The EK and AK may be NamedHandle
// or AuthHandle values; both must carry the same Names that were committed to
// at construction. The method never accepts a replacement blob or secret.
func (c *CredentialChallenge) Activate(t transport.TPM, ek handle, ak handle, s ...Session) (*CredentialChallengeResult, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil challenge", ErrCredentialChallenge)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	identity := c.identityLocked()
	switch c.state {
	case CredentialChallengeActivated:
		return nil, c.recordFailureLocked("consume", identity, nil, nil, ErrCredentialChallengeConsumed, nil)
	case CredentialChallengeFailed:
		return nil, c.recordFailureLocked("consume", identity, nil, nil, ErrCredentialChallengeState, c.lastErr)
	}

	ekName, err := resolveCredentialHandleName(t, ek, "EK")
	if err != nil {
		return nil, c.recordFailureLocked("validate_ek", identity, nil, nil, ErrCredentialChallengeIdentity, err)
	}
	akName, err := resolveCredentialHandleName(t, ak, "AK")
	if err != nil {
		return nil, c.recordFailureLocked("validate_ak", identity, nil, nil, ErrCredentialChallengeIdentity, err)
	}
	identity.EKName = ekName
	identity.AKName = akName
	if !bytes.Equal(ekName.Buffer, c.ekName.Buffer) {
		return nil, c.recordFailureLocked("validate_ek", identity, &ekName, &akName, ErrCredentialChallengeIdentity, nil)
	}
	if !bytes.Equal(akName.Buffer, c.akName.Buffer) {
		return nil, c.recordFailureLocked("validate_ak", identity, &ekName, &akName, ErrCredentialChallengeIdentity, nil)
	}
	if t == nil {
		return nil, c.recordFailureLocked("activate", identity, &ekName, &akName, ErrCredentialChallengeState, errors.New("nil TPM transport"))
	}

	rsp, err := ActivateCredential{
		ActivateHandle: credentialHandleForActivation(ak, akName),
		KeyHandle:      credentialHandleForActivation(ek, ekName),
		CredentialBlob: TPM2BIDObject{Buffer: cloneCredentialBytes(c.blob.Buffer)},
		Secret:         TPM2BEncryptedSecret{Buffer: cloneCredentialBytes(c.secret.Buffer)},
	}.Execute(t, s...)
	if err != nil {
		return nil, c.recordFailureLocked("activate_credential", identity, &ekName, &akName, ErrCredentialChallenge, err)
	}
	if !hmac.Equal(rsp.CertInfo.Buffer, c.credential) {
		c.state = CredentialChallengeFailed
		return nil, c.recordFailureLocked("validate_result", identity, &ekName, &akName, ErrCredentialChallengeResult, nil)
	}

	c.state = CredentialChallengeActivated
	c.lastErr = nil
	c.lastFailure = nil
	result := CredentialChallengeResult{
		ActivateCredentialResponse: *rsp,
		Identity:                   identity,
		State:                      c.state,
	}
	return &result, nil
}

// ActivateCredential is an alias for Activate.
func (c *CredentialChallenge) ActivateCredential(t transport.TPM, ek handle, ak handle, s ...Session) (*CredentialChallengeResult, error) {
	return c.Activate(t, ek, ak, s...)
}

// ActivateWithBlob is Activate for callers that hold the credential blob and
// encrypted secret separately. The values must be byte-for-byte identical to
// the material committed to by the challenge; a blob or secret from another
// challenge is rejected before any TPM command is sent.
func (c *CredentialChallenge) ActivateWithBlob(t transport.TPM, ek handle, ak handle, blob TPM2BIDObject, secret TPM2BEncryptedSecret, s ...Session) (*CredentialChallengeResult, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil challenge", ErrCredentialChallenge)
	}
	c.mu.Lock()
	identity := c.identityLocked()
	switch c.state {
	case CredentialChallengeActivated:
		failure := c.recordFailureLocked("consume", identity, nil, nil, ErrCredentialChallengeConsumed, nil)
		c.mu.Unlock()
		return nil, failure
	case CredentialChallengeFailed:
		failure := c.recordFailureLocked("consume", identity, nil, nil, ErrCredentialChallengeState, c.lastErr)
		c.mu.Unlock()
		return nil, failure
	}
	committedBlob := cloneCredentialBytes(c.blob.Buffer)
	committedSecret := cloneCredentialBytes(c.secret.Buffer)
	if !bytes.Equal(blob.Buffer, committedBlob) || !bytes.Equal(secret.Buffer, committedSecret) {
		failure := c.recordFailureLocked("validate_challenge", identity, nil, nil, ErrCredentialChallengeIdentity,
			errors.New("credential blob or secret does not belong to this challenge"))
		c.mu.Unlock()
		return nil, failure
	}
	c.mu.Unlock()
	return c.Activate(t, ek, ak, s...)
}

// ActivateResponse is like Activate but returns the raw TPM response.
func (c *CredentialChallenge) ActivateResponse(t transport.TPM, ek handle, ak handle, s ...Session) (*ActivateCredentialResponse, error) {
	result, err := c.Activate(t, ek, ak, s...)
	if err != nil {
		return nil, err
	}
	rsp := result.ActivateCredentialResponse
	return &rsp, nil
}

// Failure returns the most recent activation error, if any.
func (c *CredentialChallenge) Failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastFailure
}

// Report returns the challenge identity, lifecycle state and all activation
// attempts. It is safe to log because it contains no credential material.
func (c *CredentialChallenge) Report() CredentialChallengeReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CredentialChallengeReport{
		Identity: c.identityLocked(),
		State:    c.state,
		Attempts: cloneCredentialAttempts(c.attempts),
		Err:      c.lastFailure,
	}
}

// CredentialChallengeSnapshot is a serializable, consistency-protected
// snapshot of a challenge. A snapshot can be persisted so a process restart
// cannot make a consumed challenge usable again. RestoreCredentialChallenge
// verifies the checksum and re-derives every identity value before returning a
// challenge. Callers that put snapshots in adversarial storage must protect
// them with their own authenticated storage.
type CredentialChallengeSnapshot struct {
	Version        uint32
	ID             [32]byte
	EKPublic       []byte
	EKName         []byte
	AKName         []byte
	Credential     []byte
	CredentialBlob []byte
	Secret         []byte
	State          CredentialChallengeState
	Attempts       []CredentialChallengeAttemptSnapshot
	Checksum       [32]byte
}

// Snapshot returns a deep copy of the challenge suitable for persisting. The
// snapshot contains the plaintext credential value and must be handled as
// sensitive material.
func (c *CredentialChallenge) Snapshot() CredentialChallengeSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := CredentialChallengeSnapshot{
		Version:        credentialChallengeVersion,
		ID:             c.id,
		EKPublic:       cloneCredentialBytes(c.ekPublicBytes),
		EKName:         cloneCredentialBytes(c.ekName.Buffer),
		AKName:         cloneCredentialBytes(c.akName.Buffer),
		Credential:     cloneCredentialBytes(c.credential),
		CredentialBlob: cloneCredentialBytes(c.blob.Buffer),
		Secret:         cloneCredentialBytes(c.secret.Buffer),
		State:          c.state,
		Attempts:       snapshotCredentialAttempts(c.attempts),
	}
	snapshot.Checksum = credentialChallengeChecksum(snapshot)
	return snapshot
}

// RestoreCredentialChallenge restores a challenge snapshot and verifies that
// the EK public area, EK Name, AK Name, credential blob, secret, credential
// value and lifecycle state all belong to the same transaction.
func RestoreCredentialChallenge(snapshot CredentialChallengeSnapshot) (*CredentialChallenge, error) {
	if snapshot.Version != credentialChallengeVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCredentialChallengeSnapshot, snapshot.Version)
	}
	if snapshot.Checksum != credentialChallengeChecksum(snapshot) {
		return nil, fmt.Errorf("%w: checksum mismatch", ErrCredentialChallengeSnapshot)
	}
	switch snapshot.State {
	case CredentialChallengeReady, CredentialChallengeActivated, CredentialChallengeFailed:
	default:
		return nil, fmt.Errorf("%w: unknown state %d", ErrCredentialChallengeSnapshot, snapshot.State)
	}
	public, err := Unmarshal[TPMTPublic](snapshot.EKPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing EK public area: %v", ErrCredentialChallengeSnapshot, err)
	}
	c, err := newCredentialChallenge(public, TPM2BName{Buffer: cloneCredentialBytes(snapshot.AKName)}, snapshot.Credential, snapshot.CredentialBlob, snapshot.Secret)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialChallengeSnapshot, err)
	}
	if !bytes.Equal(c.ekName.Buffer, snapshot.EKName) || c.id != snapshot.ID {
		return nil, fmt.Errorf("%w: identity changed while restoring", ErrCredentialChallengeSnapshot)
	}
	c.state = snapshot.State
	c.attempts = restoreCredentialAttempts(snapshot.Attempts)
	if c.state == CredentialChallengeFailed {
		c.lastFailure = &CredentialChallengeError{
			Stage:    "restore",
			Identity: c.identityLocked(),
			Kind:     ErrCredentialChallengeState,
			Err:      errors.New("challenge was persisted in a failed state"),
		}
	}
	return c, nil
}

// RestoreChallenge is an alias for RestoreCredentialChallenge.
func RestoreChallenge(snapshot CredentialChallengeSnapshot) (*CredentialChallenge, error) {
	return RestoreCredentialChallenge(snapshot)
}

// Save writes a snapshot to w as JSON. The snapshot is consistency-protected
// but is not an authenticity token; callers that persist it in adversarial
// storage must protect it with their own authenticated storage.
func (c *CredentialChallenge) Save(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("%w: nil snapshot writer", ErrCredentialChallengeSnapshot)
	}
	return json.NewEncoder(w).Encode(c.Snapshot())
}

// LoadCredentialChallenge reads a snapshot written by Save and restores it.
func LoadCredentialChallenge(r io.Reader) (*CredentialChallenge, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil snapshot reader", ErrCredentialChallengeSnapshot)
	}
	var snapshot CredentialChallengeSnapshot
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("%w: decoding snapshot: %v", ErrCredentialChallengeSnapshot, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: multiple snapshots in one stream", ErrCredentialChallengeSnapshot)
		}
		return nil, fmt.Errorf("%w: trailing snapshot data: %v", ErrCredentialChallengeSnapshot, err)
	}
	return RestoreCredentialChallenge(snapshot)
}

func (c *CredentialChallenge) identityLocked() CredentialChallengeIdentity {
	return CredentialChallengeIdentity{
		ChallengeID:      c.id,
		EKName:           cloneCredentialName(c.ekName),
		EKPublicDigest:   c.ekPublicDigest,
		AKName:           cloneCredentialName(c.akName),
		CredentialDigest: c.credentialDigest,
		BlobDigest:       sha256.Sum256(c.blob.Buffer),
		SecretDigest:     sha256.Sum256(c.secret.Buffer),
	}
}

func (c *CredentialChallenge) computeID() [32]byte {
	h := sha256.New()
	writeCredentialChallengeField(h, c.ekPublicBytes)
	writeCredentialChallengeField(h, c.ekName.Buffer)
	writeCredentialChallengeField(h, c.akName.Buffer)
	writeCredentialChallengeField(h, c.credential)
	writeCredentialChallengeField(h, c.blob.Buffer)
	writeCredentialChallengeField(h, c.secret.Buffer)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

func (c *CredentialChallenge) recordFailureLocked(stage string, identity CredentialChallengeIdentity, ekName, akName *TPM2BName, kind, cause error) error {
	if ekName != nil {
		identity.EKName = cloneCredentialName(*ekName)
	}
	if akName != nil {
		identity.AKName = cloneCredentialName(*akName)
	}
	if cause != nil {
		c.lastErr = cause
	} else {
		c.lastErr = kind
	}
	attemptErr := cause
	if attemptErr == nil {
		attemptErr = kind
	}
	c.attempts = append(c.attempts, CredentialChallengeAttempt{
		Stage:            stage,
		EKName:           cloneCredentialName(identity.EKName),
		AKName:           cloneCredentialName(identity.AKName),
		EKPublicDigest:   identity.EKPublicDigest,
		CredentialDigest: identity.CredentialDigest,
		BlobDigest:       identity.BlobDigest,
		SecretDigest:     identity.SecretDigest,
		Err:              attemptErr,
	})
	failure := &CredentialChallengeError{Stage: stage, Identity: identity, Kind: kind, Err: cause}
	c.lastFailure = failure
	return failure
}

func resolveCredentialHandleName(t transport.TPM, h handle, role string) (TPM2BName, error) {
	if h == nil {
		return TPM2BName{}, fmt.Errorf("nil %s handle", role)
	}
	name := h.KnownName()
	if name != nil && len(name.Buffer) != 0 {
		if err := validateCredentialObjectName(*name); err != nil {
			return TPM2BName{}, fmt.Errorf("%s: %w", role, err)
		}
	}
	if t == nil {
		if name != nil && len(name.Buffer) != 0 {
			return cloneCredentialName(*name), nil
		}
		return TPM2BName{}, fmt.Errorf("%s handle does not carry a known TPM Name and no TPM is available", role)
	}
	// ReadPublic has no authorization sessions, so the handle Name is not
	// used for the command. Supply the caller's Name only to the command
	// builder; the TPM reports the authoritative public area and Name.
	readHandle := NamedHandle{Handle: TPMHandle(h.HandleValue())}
	if name != nil {
		readHandle.Name = cloneCredentialName(*name)
	}
	rsp, err := ReadPublic{ObjectHandle: readHandle}.Execute(t)
	if err != nil {
		return TPM2BName{}, fmt.Errorf("reading %s public area: %w", role, err)
	}
	if err := validateCredentialObjectName(rsp.Name); err != nil {
		return TPM2BName{}, fmt.Errorf("%s: %w", role, err)
	}
	if name != nil && len(name.Buffer) != 0 && !bytes.Equal(name.Buffer, rsp.Name.Buffer) {
		return TPM2BName{}, fmt.Errorf("%s handle Name %x does not match TPM Name %x",
			role, name.Buffer, rsp.Name.Buffer)
	}
	return cloneCredentialName(rsp.Name), nil
}

func credentialHandleForActivation(h handle, name TPM2BName) handle {
	switch value := h.(type) {
	case AuthHandle:
		value.Name = cloneCredentialName(name)
		return value
	case *AuthHandle:
		if value != nil {
			copy := *value
			copy.Name = cloneCredentialName(name)
			return copy
		}
	case NamedHandle:
		value.Name = cloneCredentialName(name)
		return value
	case *NamedHandle:
		if value != nil {
			copy := *value
			copy.Name = cloneCredentialName(name)
			return copy
		}
	default:
	}
	return NamedHandle{Handle: TPMHandle(h.HandleValue()), Name: cloneCredentialName(name)}
}

func cloneCredentialPublic(public *TPMTPublic) (clone *TPMTPublic, err error) {
	if public == nil {
		return nil, fmt.Errorf("%w: nil EK public area", ErrCredentialChallenge)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			clone = nil
			err = fmt.Errorf("%w: malformed EK public area: %v", ErrCredentialChallenge, recovered)
		}
	}()
	clone, err = Unmarshal[TPMTPublic](Marshal(*public))
	if err != nil {
		return nil, fmt.Errorf("copying EK public area: %w", err)
	}
	return clone, nil
}

func validateCredentialAKName(name TPM2BName) error {
	return validateCredentialObjectName(name)
}

func validateCredentialObjectName(name TPM2BName) error {
	if len(name.Buffer) < 2 {
		return fmt.Errorf("%w: Name has %d bytes", ErrCredentialChallengeName, len(name.Buffer))
	}
	alg := TPMAlgID(binary.BigEndian.Uint16(name.Buffer[:2]))
	hash, err := alg.Hash()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialChallengeName, err)
	}
	if want := 2 + hash.Size(); len(name.Buffer) != want {
		return fmt.Errorf("%w: NameAlg %v requires %d bytes, got %d",
			ErrCredentialChallengeName, alg, want, len(name.Buffer))
	}
	return nil
}

func credentialBlobHMACSize(blob TPM2BIDObject) (int, error) {
	if len(blob.Buffer) < 2 {
		return 0, fmt.Errorf("%w: blob has %d bytes", ErrCredentialChallengeBlob, len(blob.Buffer))
	}
	size := int(binary.BigEndian.Uint16(blob.Buffer[:2]))
	if size <= 0 || size > credentialMaxDigestSize {
		return 0, fmt.Errorf("%w: integrity HMAC has %d bytes", ErrCredentialChallengeBlob, size)
	}
	if len(blob.Buffer) <= 2+size {
		return 0, fmt.Errorf("%w: missing encrypted credential", ErrCredentialChallengeBlob)
	}
	return size, nil
}

func validateCredentialBlob(blob TPM2BIDObject) error {
	_, err := credentialBlobHMACSize(blob)
	return err
}

func validateCredentialBlobHash(blob TPM2BIDObject, keyName TPM2BName) error {
	if err := validateCredentialBlob(blob); err != nil {
		return err
	}
	if err := validateCredentialObjectName(keyName); err != nil {
		return err
	}
	size, _ := credentialBlobHMACSize(blob)
	alg := TPMAlgID(binary.BigEndian.Uint16(keyName.Buffer[:2]))
	hash, err := alg.Hash()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialChallengeName, err)
	}
	if size != hash.Size() {
		return fmt.Errorf("%w: blob HMAC is %d bytes for EK NameAlg %v (expected %d)",
			ErrCredentialChallengeBlob, size, alg, hash.Size())
	}
	return nil
}

func validateCredentialPublicName(public TPM2BPublic, name TPM2BName) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: malformed public area: %v", ErrCredentialChallengeName, recovered)
		}
	}()
	contents, err := public.Contents()
	if err != nil {
		return fmt.Errorf("%w: parsing public area: %v", ErrCredentialChallengeName, err)
	}
	want, err := ObjectName(contents)
	if err != nil {
		return fmt.Errorf("%w: computing object Name: %v", ErrCredentialChallengeName, err)
	}
	if len(name.Buffer) == 0 || !bytes.Equal(want.Buffer, name.Buffer) {
		return fmt.Errorf("%w: TPM returned Name %x for public area with Name %x",
			ErrCredentialChallengeIdentity, name.Buffer, want.Buffer)
	}
	return nil
}

func cloneCredentialBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

func cloneCredentialName(name TPM2BName) TPM2BName {
	return TPM2BName{Buffer: cloneCredentialBytes(name.Buffer)}
}

func cloneCredentialAttempts(attempts []CredentialChallengeAttempt) []CredentialChallengeAttempt {
	if attempts == nil {
		return nil
	}
	result := make([]CredentialChallengeAttempt, len(attempts))
	for i, attempt := range attempts {
		result[i] = attempt
		result[i].EKName = cloneCredentialName(attempt.EKName)
		result[i].AKName = cloneCredentialName(attempt.AKName)
	}
	return result
}

func snapshotCredentialAttempts(attempts []CredentialChallengeAttempt) []CredentialChallengeAttemptSnapshot {
	if attempts == nil {
		return nil
	}
	result := make([]CredentialChallengeAttemptSnapshot, len(attempts))
	for i, attempt := range attempts {
		result[i] = CredentialChallengeAttemptSnapshot{
			Stage:            attempt.Stage,
			EKName:           cloneCredentialBytes(attempt.EKName.Buffer),
			AKName:           cloneCredentialBytes(attempt.AKName.Buffer),
			EKPublicDigest:   attempt.EKPublicDigest,
			CredentialDigest: attempt.CredentialDigest,
			BlobDigest:       attempt.BlobDigest,
			SecretDigest:     attempt.SecretDigest,
		}
		if attempt.Err != nil {
			result[i].Error = attempt.Err.Error()
		}
	}
	return result
}

func restoreCredentialAttempts(attempts []CredentialChallengeAttemptSnapshot) []CredentialChallengeAttempt {
	if attempts == nil {
		return nil
	}
	result := make([]CredentialChallengeAttempt, len(attempts))
	for i, attempt := range attempts {
		result[i] = CredentialChallengeAttempt{
			Stage:            attempt.Stage,
			EKName:           TPM2BName{Buffer: cloneCredentialBytes(attempt.EKName)},
			AKName:           TPM2BName{Buffer: cloneCredentialBytes(attempt.AKName)},
			EKPublicDigest:   attempt.EKPublicDigest,
			CredentialDigest: attempt.CredentialDigest,
			BlobDigest:       attempt.BlobDigest,
			SecretDigest:     attempt.SecretDigest,
		}
		if attempt.Error != "" {
			result[i].Err = errors.New(attempt.Error)
		}
	}
	return result
}

func writeCredentialChallengeField(w io.Writer, field []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(field)
}

func credentialChallengeChecksum(snapshot CredentialChallengeSnapshot) [32]byte {
	h := sha256.New()
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], snapshot.Version)
	h.Write(version[:])
	h.Write(snapshot.ID[:])
	writeCredentialChallengeField(h, snapshot.EKPublic)
	writeCredentialChallengeField(h, snapshot.EKName)
	writeCredentialChallengeField(h, snapshot.AKName)
	writeCredentialChallengeField(h, snapshot.Credential)
	writeCredentialChallengeField(h, snapshot.CredentialBlob)
	writeCredentialChallengeField(h, snapshot.Secret)
	h.Write([]byte{byte(snapshot.State)})
	for _, attempt := range snapshot.Attempts {
		writeCredentialChallengeField(h, []byte(attempt.Stage))
		writeCredentialChallengeField(h, attempt.EKName)
		writeCredentialChallengeField(h, attempt.AKName)
		h.Write(attempt.EKPublicDigest[:])
		h.Write(attempt.CredentialDigest[:])
		h.Write(attempt.BlobDigest[:])
		h.Write(attempt.SecretDigest[:])
		writeCredentialChallengeField(h, []byte(attempt.Error))
	}
	var checksum [32]byte
	copy(checksum[:], h.Sum(nil))
	return checksum
}
