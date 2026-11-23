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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"sort"

	"github.com/google/go-tpm/tpmutil"
)

// QuoteAttestation bundles the products of a single attestation transaction:
// the quote blob returned by TPM2_Quote, its signature, the PCR selection
// the quote covers, and the PCR snapshot that the quote was checked against
// at generation time.
//
// The bundle is the unit of verification: VerifyQuote derives the PCR digest
// exclusively from the bundled snapshot and requires it to match the digest
// signed by the TPM, so a digest or PCR values read at a different time
// cannot be stitched onto the quote to form a valid proof.
type QuoteAttestation struct {
	// Quote is the raw TPMS_ATTEST blob returned by TPM2_Quote.
	Quote []byte
	// Signature is the decoded signature over Quote.
	Signature *Signature
	// Selection is the PCR selection covered by the quote.
	Selection PCRSelection
	// PCRs is the snapshot of PCR values validated against the quote in the
	// same attestation transaction. It contains exactly the PCRs named by
	// Selection.
	PCRs map[int][]byte
	// ExtraData is the qualifying data echoed by the TPM in the quote.
	ExtraData []byte
}

// maxAttestationAttempts bounds how many times AttestQuote re-runs the
// snapshot-quote-check sequence when a PCR changes in the middle of an
// attempt.
const maxAttestationAttempts = 4

// AttestQuote runs an attestation transaction: it snapshots the PCRs named
// by sel, quotes them with the given signing key, and only returns once the
// quote blob, the PCR selection, and the PCR snapshot are known to belong to
// the same transaction.
//
// If a PCR is extended between the snapshot and the quote, the inconsistent
// pair is discarded (neither half is returned or reused) and the transaction
// is retried with a fresh snapshot and a fresh quote. An error is returned
// if the PCRs do not stabilize within maxAttestationAttempts attempts.
//
// extraData is passed to the TPM as qualifying data and is bound into the
// signed quote blob. sigAlg is forwarded to Quote; pass AlgNull to use the
// signing key's scheme.
func AttestQuote(rw io.ReadWriter, signingHandle tpmutil.Handle, signerAuth string, extraData []byte, sel PCRSelection, sigAlg Algorithm) (*QuoteAttestation, error) {
	for attempt := 1; ; attempt++ {
		att, retry, err := attestQuoteOnce(rw, signingHandle, signerAuth, extraData, sel, sigAlg)
		if err != nil {
			return nil, err
		}
		if !retry {
			return att, nil
		}
		if attempt == maxAttestationAttempts {
			return nil, fmt.Errorf("pcrs changed during %d consecutive attestation attempts; could not obtain a consistent quote", maxAttestationAttempts)
		}
	}
}

// attestQuoteOnce performs a single snapshot-quote-check pass. It returns
// retry=true if the PCRs changed between the snapshot and the quote, in
// which case both the snapshot and the quote are discarded.
func attestQuoteOnce(rw io.ReadWriter, signingHandle tpmutil.Handle, signerAuth string, extraData []byte, sel PCRSelection, sigAlg Algorithm) (*QuoteAttestation, bool, error) {
	// Snapshot the selected PCRs.
	snapshot, err := ReadPCRs(rw, sel)
	if err != nil {
		return nil, false, fmt.Errorf("reading PCR snapshot: %v", err)
	}
	// Quote the same selection.
	quote, sig, err := Quote(rw, signingHandle, signerAuth, "", extraData, sel, sigAlg)
	if err != nil {
		return nil, false, fmt.Errorf("quoting PCRs: %v", err)
	}
	// Bind the quote and the snapshot into one transaction before either
	// is allowed to escape.
	ad, err := DecodeAttestationData(quote)
	if err != nil {
		return nil, false, fmt.Errorf("decoding quote: %v", err)
	}
	if ad.Type != TagAttestQuote || ad.AttestedQuoteInfo == nil {
		return nil, false, fmt.Errorf("attestation is not a quote (type 0x%x)", ad.Type)
	}
	if !samePCRSelection(ad.AttestedQuoteInfo.PCRSelection, sel) {
		return nil, false, fmt.Errorf("quote PCR selection %+v does not match requested selection %+v", ad.AttestedQuoteInfo.PCRSelection, sel)
	}
	if !bytes.Equal([]byte(ad.ExtraData), extraData) {
		return nil, false, fmt.Errorf("quote extraData does not match the attestation request")
	}
	digest, err := snapshotPCRDigest(sel, snapshot)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(digest, ad.AttestedQuoteInfo.PCRDigest) {
		// A PCR was extended between the snapshot and the quote. Discard
		// both halves so a digest from this snapshot can never be paired
		// with a signature from another one.
		return nil, true, nil
	}
	return &QuoteAttestation{
		Quote:     quote,
		Signature: sig,
		Selection: sel,
		PCRs:      snapshot,
		ExtraData: append([]byte(nil), extraData...),
	}, false, nil
}

// VerifyQuote verifies a QuoteAttestation against the signer's public key
// and the expected extraData.
//
// Verification is self-contained in the bundle: the PCR digest is recomputed
// from att.PCRs (the snapshot captured in the same transaction as the quote)
// and must equal the digest inside the signed quote blob, the bundled
// selection must equal the signed selection, and extraData must match the
// signed qualifying data. Callers cannot substitute freshly read PCRs or a
// digest from another snapshot: any PCR change after the transaction, or any
// mix-and-match of snapshot and signature across transactions, fails
// verification.
func VerifyQuote(pub crypto.PublicKey, extraData []byte, att *QuoteAttestation) error {
	if att == nil {
		return fmt.Errorf("attestation is nil")
	}
	ad, err := DecodeAttestationData(att.Quote)
	if err != nil {
		return fmt.Errorf("decoding quote: %v", err)
	}
	if ad.Type != TagAttestQuote || ad.AttestedQuoteInfo == nil {
		return fmt.Errorf("attestation is not a quote (type 0x%x)", ad.Type)
	}
	// The bundled selection must be the one the TPM signed; otherwise the
	// snapshot could describe different PCRs than the quote covers.
	if !samePCRSelection(ad.AttestedQuoteInfo.PCRSelection, att.Selection) {
		return fmt.Errorf("quote PCR selection %+v does not match attestation selection %+v", ad.AttestedQuoteInfo.PCRSelection, att.Selection)
	}
	// Recompute the PCR digest from the bundled snapshot and require it to
	// match the signed digest. The digest is never taken from caller input,
	// so a digest from another snapshot cannot be stitched onto this
	// signature.
	digest, err := snapshotPCRDigest(att.Selection, att.PCRs)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, ad.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("pcr snapshot digest does not match the quoted digest")
	}
	if !bytes.Equal([]byte(ad.ExtraData), extraData) {
		return fmt.Errorf("extraData does not match the quote")
	}
	if !bytes.Equal([]byte(ad.ExtraData), att.ExtraData) {
		return fmt.Errorf("bundled extraData does not match the quote")
	}
	if err := verifyQuoteSignature(pub, att.Signature, att.Quote); err != nil {
		return fmt.Errorf("verifying quote signature: %v", err)
	}
	return nil
}

// Verify verifies the attestation against the signer's public key and the
// expected extraData. It is equivalent to VerifyQuote(pub, extraData, a).
func (a *QuoteAttestation) Verify(pub crypto.PublicKey, extraData []byte) error {
	return VerifyQuote(pub, extraData, a)
}

// verifyQuoteSignature verifies sig over the quote blob with pub.
func verifyQuoteSignature(pub crypto.PublicKey, sig *Signature, quote []byte) error {
	if sig == nil {
		return fmt.Errorf("missing signature")
	}
	var hashAlg Algorithm
	switch sig.Alg {
	case AlgRSASSA, AlgRSAPSS:
		if sig.RSA == nil {
			return fmt.Errorf("missing RSA signature")
		}
		hashAlg = sig.RSA.HashAlg
	case AlgECDSA:
		if sig.ECC == nil {
			return fmt.Errorf("missing ECC signature")
		}
		hashAlg = sig.ECC.HashAlg
	default:
		return fmt.Errorf("unsupported signature algorithm 0x%x", sig.Alg)
	}
	h, err := hashAlg.Hash()
	if err != nil {
		return err
	}
	hh := h.New()
	hh.Write(quote)
	digest := hh.Sum(nil)

	switch sig.Alg {
	case AlgRSASSA:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("rsassa signature requires an RSA public key, got %T", pub)
		}
		return rsa.VerifyPKCS1v15(rsaPub, h, digest, sig.RSA.Signature)
	case AlgRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("rsapss signature requires an RSA public key, got %T", pub)
		}
		return rsa.VerifyPSS(rsaPub, h, digest, sig.RSA.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	case AlgECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ecdsa signature requires an ECDSA public key, got %T", pub)
		}
		if !ecdsa.Verify(ecPub, digest, sig.ECC.R, sig.ECC.S) {
			return fmt.Errorf("ecdsa signature verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported signature algorithm 0x%x", sig.Alg)
}

// canonicalPCRList returns the sorted, de-duplicated PCR indices of pcrs.
func canonicalPCRList(pcrs []int) []int {
	seen := make(map[int]struct{}, len(pcrs))
	out := make([]int, 0, len(pcrs))
	for _, p := range pcrs {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// samePCRSelection reports whether a and b name the same hash algorithm and
// the same set of PCRs, regardless of ordering or duplicates.
func samePCRSelection(a, b PCRSelection) bool {
	if a.Hash != b.Hash {
		return false
	}
	ap, bp := canonicalPCRList(a.PCRs), canonicalPCRList(b.PCRs)
	if len(ap) != len(bp) {
		return false
	}
	for i := range ap {
		if ap[i] != bp[i] {
			return false
		}
	}
	return true
}

// snapshotPCRDigest computes the PCR digest recorded in TPMS_QUOTE_INFO for
// the given selection over the PCR values in snapshot. The snapshot must
// cover exactly the selected PCRs: a missing or extra PCR is an error, so a
// partial or extended snapshot cannot silently produce a matching digest.
func snapshotPCRDigest(sel PCRSelection, snapshot map[int][]byte) ([]byte, error) {
	h, err := sel.Hash.Hash()
	if err != nil {
		return nil, fmt.Errorf("pcr selection hash: %v", err)
	}
	pcrs := canonicalPCRList(sel.PCRs)
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("pcr selection is empty")
	}
	if len(snapshot) != len(pcrs) {
		return nil, fmt.Errorf("pcr snapshot covers %d PCRs, selection covers %d", len(snapshot), len(pcrs))
	}
	hash := h.New()
	for _, pcr := range pcrs {
		val, ok := snapshot[pcr]
		if !ok {
			return nil, fmt.Errorf("pcr snapshot is missing PCR %d", pcr)
		}
		hash.Write(val)
	}
	return hash.Sum(nil), nil
}
