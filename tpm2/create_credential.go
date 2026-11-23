package tpm2

import (
	"errors"
	"io"
)

var (
	labelIdentity = "IDENTITY"
)

// CreateCredential creates an encrypted secret that can be recovered using ActivateCredential as part of a key-attestation flow.
func CreateCredential(rand io.Reader, pub LabeledEncapsulationKey, name []byte, credentialValue []byte) (idObject []byte, encSecret []byte, err error) {
	if rand == nil {
		return nil, nil, errors.New("tpm2: nil random source")
	}
	if pub == nil {
		return nil, nil, errors.New("tpm2: nil encapsulation key")
	}
	// The Name is part of both the credential encryption context and the
	// integrity HMAC. Snapshot it before doing any cryptography so a caller
	// cannot change the two halves of the challenge independently.
	name = cloneCredentialBytes(name)
	if err := validateCredentialAKName(TPM2BName{Buffer: name}); err != nil {
		return nil, nil, err
	}
	if len(credentialValue) > 65535 {
		return nil, nil, ErrCredentialChallengeCredential
	}
	credentialValue = cloneCredentialBytes(credentialValue)

	secret, ciphertext, err := pub.Encapsulate(rand, labelIdentity)
	if err != nil {
		return nil, nil, err
	}
	if len(secret) == 0 || len(ciphertext) == 0 {
		return nil, nil, errors.New("tpm2: encapsulation produced empty output")
	}

	// Marshal the credentialValue as a TPM2B_DIGEST before encrypting it.
	// See Part 1, "Credential Protection", and Part 2, "TPMS_ID_OBJECT".
	credential2B := Marshal(TPM2BDigest{Buffer: credentialValue})

	// Encrypt the marshalled credential as encIdentity.
	encIdentity, err := deriveAndEncrypt(pub, secret, name, credential2B)
	if err != nil {
		return nil, nil, err
	}

	// Compute the HMAC of (encIdentity || name)
	identityHMAC, err := deriveAndHMAC(pub, secret, nil, encIdentity, name)
	if err != nil {
		return nil, nil, err
	}

	// Marshal the virtual TPMS_ID_OBJECT ourselves. We have to do this since encIdentity's size is encrypted.
	idObject = make([]byte, 0, 2+len(identityHMAC)+len(encIdentity))
	idObject = append(idObject, Marshal(TPM2BDigest{Buffer: identityHMAC})...)
	idObject = append(idObject, encIdentity...)

	return idObject, ciphertext, nil
}
