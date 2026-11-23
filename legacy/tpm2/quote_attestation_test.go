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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// makeQuoteBlob builds a signed-quote-shaped TPMS_ATTEST blob for the given
// selection, PCR digest and extraData, as a TPM would have produced it.
func makeQuoteBlob(t *testing.T, sel PCRSelection, pcrDigest, extraData []byte) []byte {
	t.Helper()
	ad := AttestationData{
		Magic:           0xff544347,
		Type:            TagAttestQuote,
		ExtraData:       extraData,
		FirmwareVersion: 1,
		AttestedQuoteInfo: &QuoteInfo{
			PCRSelection: sel,
			PCRDigest:    pcrDigest,
		},
	}
	blob, err := ad.Encode()
	if err != nil {
		t.Fatalf("encoding attestation data: %v", err)
	}
	return blob
}

func signQuoteBlob(t *testing.T, key *rsa.PrivateKey, blob []byte) *Signature {
	t.Helper()
	digest := sha256.Sum256(blob)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing quote blob: %v", err)
	}
	return &Signature{
		Alg: AlgRSASSA,
		RSA: &SignatureRSA{HashAlg: AlgSHA256, Signature: sig},
	}
}

// transact builds a consistent QuoteAttestation the way AttestQuote would:
// the digest inside the signed blob is derived from the given snapshot.
func transact(t *testing.T, key *rsa.PrivateKey, sel PCRSelection, snapshot map[int][]byte, extraData []byte) *QuoteAttestation {
	t.Helper()
	digest, err := snapshotPCRDigest(sel, snapshot)
	if err != nil {
		t.Fatalf("computing snapshot digest: %v", err)
	}
	blob := makeQuoteBlob(t, sel, digest, extraData)
	return &QuoteAttestation{
		Quote:     blob,
		Signature: signQuoteBlob(t, key, blob),
		Selection: sel,
		PCRs:      snapshot,
		ExtraData: extraData,
	}
}

func cloneSnapshot(snapshot map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(snapshot))
	for pcr, val := range snapshot {
		out[pcr] = append([]byte(nil), val...)
	}
	return out
}

func TestVerifyQuoteValid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7, 4}}
	snapshot := map[int][]byte{
		4: make([]byte, 32),
		7: make([]byte, 32),
	}
	extraData := []byte("nonce-from-verifier")
	att := transact(t, key, sel, snapshot, extraData)

	if err := VerifyQuote(&key.PublicKey, extraData, att); err != nil {
		t.Errorf("VerifyQuote() failed for a consistent attestation: %v", err)
	}
	if err := att.Verify(&key.PublicKey, extraData); err != nil {
		t.Errorf("att.Verify() failed for a consistent attestation: %v", err)
	}
}

func TestVerifyQuoteECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	snapshot := map[int][]byte{7: make([]byte, 32)}
	extraData := []byte("nonce")

	digest, err := snapshotPCRDigest(sel, snapshot)
	if err != nil {
		t.Fatalf("computing snapshot digest: %v", err)
	}
	blob := makeQuoteBlob(t, sel, digest, extraData)
	h := sha256.Sum256(blob)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("signing quote blob: %v", err)
	}
	att := &QuoteAttestation{
		Quote:     blob,
		Signature: &Signature{Alg: AlgECDSA, ECC: &SignatureECC{HashAlg: AlgSHA256, R: r, S: s}},
		Selection: sel,
		PCRs:      snapshot,
		ExtraData: extraData,
	}
	if err := VerifyQuote(&key.PublicKey, extraData, att); err != nil {
		t.Errorf("VerifyQuote() failed for a consistent ECDSA attestation: %v", err)
	}
}

// A PCR extended after the attestation transaction must not verify against
// the old quote, even if the caller re-reads the PCRs and presents the fresh
// snapshot together with the old quote and signature.
func TestVerifyQuotePCRChangedAfterTransaction(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	snapshot := map[int][]byte{7: make([]byte, 32)}
	extraData := []byte("nonce")
	att := transact(t, key, sel, snapshot, extraData)

	// The target PCR is extended after the quote was generated.
	extended := cloneSnapshot(snapshot)
	h := sha256.New()
	h.Write(snapshot[7])
	h.Write([]byte("event"))
	extended[7] = h.Sum(nil)

	stale := *att
	stale.PCRs = extended
	if err := VerifyQuote(&key.PublicKey, extraData, &stale); err == nil {
		t.Error("VerifyQuote() succeeded with a post-transaction PCR snapshot stitched onto the old quote, want failure")
	}
}

// After a quote retry, mixing the signature of one transaction with the
// snapshot or blob of another must not produce a valid proof.
func TestVerifyQuoteCannotMixTransactions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	extraData := []byte("nonce")

	snapshot1 := map[int][]byte{7: make([]byte, 32)}
	first := transact(t, key, sel, snapshot1, extraData)

	// PCR 7 changes, the caller retries and gets a second transaction.
	snapshot2 := map[int][]byte{7: append(make([]byte, 31), 1)}
	second := transact(t, key, sel, snapshot2, extraData)

	// Old blob, new signature, old snapshot.
	mixed := &QuoteAttestation{
		Quote:     first.Quote,
		Signature: second.Signature,
		Selection: sel,
		PCRs:      snapshot1,
		ExtraData: extraData,
	}
	if err := VerifyQuote(&key.PublicKey, extraData, mixed); err == nil {
		t.Error("VerifyQuote() succeeded with a signature from a retry stitched onto the old quote, want failure")
	}

	// New blob and signature, but the digest of the old snapshot.
	mixed = &QuoteAttestation{
		Quote:     second.Quote,
		Signature: second.Signature,
		Selection: sel,
		PCRs:      snapshot1,
		ExtraData: extraData,
	}
	if err := VerifyQuote(&key.PublicKey, extraData, mixed); err == nil {
		t.Error("VerifyQuote() succeeded with a digest from another snapshot stitched onto the new quote, want failure")
	}

	// Both original transactions still verify on their own.
	if err := VerifyQuote(&key.PublicKey, extraData, first); err != nil {
		t.Errorf("VerifyQuote() failed for the first transaction: %v", err)
	}
	if err := VerifyQuote(&key.PublicKey, extraData, second); err != nil {
		t.Errorf("VerifyQuote() failed for the retried transaction: %v", err)
	}
}

func TestVerifyQuoteSelectionMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	snapshot := map[int][]byte{7: make([]byte, 32)}
	extraData := []byte("nonce")
	att := transact(t, key, sel, snapshot, extraData)

	// The bundled selection names different PCRs than the signed quote.
	wider := *att
	wider.Selection = PCRSelection{Hash: AlgSHA256, PCRs: []int{4, 7}}
	wider.PCRs = map[int][]byte{4: make([]byte, 32), 7: make([]byte, 32)}
	if err := VerifyQuote(&key.PublicKey, extraData, &wider); err == nil {
		t.Error("VerifyQuote() succeeded with a selection wider than the signed one, want failure")
	}

	// Same PCRs but a different hash algorithm is a different selection.
	otherHash := *att
	otherHash.Selection = PCRSelection{Hash: AlgSHA1, PCRs: []int{7}}
	if err := VerifyQuote(&key.PublicKey, extraData, &otherHash); err == nil {
		t.Error("VerifyQuote() succeeded with a different selection hash, want failure")
	}
}

func TestVerifyQuoteExtraData(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	snapshot := map[int][]byte{7: make([]byte, 32)}
	extraData := []byte("nonce")
	att := transact(t, key, sel, snapshot, extraData)

	if err := VerifyQuote(&key.PublicKey, []byte("other-nonce"), att); err == nil {
		t.Error("VerifyQuote() succeeded with mismatched extraData, want failure")
	}

	tampered := *att
	tampered.ExtraData = []byte("other-nonce")
	if err := VerifyQuote(&key.PublicKey, extraData, &tampered); err == nil {
		t.Error("VerifyQuote() succeeded with tampered bundled extraData, want failure")
	}
}

// The snapshot must cover exactly the selected PCRs: non-target PCRs smuggled
// into the snapshot, or missing target PCRs, break the transaction.
func TestVerifyQuoteSnapshotCover(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sel := PCRSelection{Hash: AlgSHA256, PCRs: []int{7}}
	snapshot := map[int][]byte{7: make([]byte, 32)}
	extraData := []byte("nonce")
	att := transact(t, key, sel, snapshot, extraData)

	withExtra := *att
	withExtra.PCRs = cloneSnapshot(snapshot)
	withExtra.PCRs[4] = make([]byte, 32)
	if err := VerifyQuote(&key.PublicKey, extraData, &withExtra); err == nil {
		t.Error("VerifyQuote() succeeded with a non-target PCR in the snapshot, want failure")
	}

	missing := *att
	missing.PCRs = map[int][]byte{}
	if err := VerifyQuote(&key.PublicKey, extraData, &missing); err == nil {
		t.Error("VerifyQuote() succeeded with a missing PCR in the snapshot, want failure")
	}
}

func TestSnapshotPCRDigestCanonical(t *testing.T) {
	snapshot := map[int][]byte{
		4: {1, 2, 3},
		7: {4, 5, 6},
	}
	a, err := snapshotPCRDigest(PCRSelection{Hash: AlgSHA256, PCRs: []int{7, 4}}, snapshot)
	if err != nil {
		t.Fatalf("snapshotPCRDigest() failed: %v", err)
	}
	b, err := snapshotPCRDigest(PCRSelection{Hash: AlgSHA256, PCRs: []int{4, 7, 7}}, snapshot)
	if err != nil {
		t.Fatalf("snapshotPCRDigest() failed: %v", err)
	}
	if string(a) != string(b) {
		t.Error("snapshotPCRDigest() depends on selection order or duplicates, want canonical digest")
	}
	if _, err := snapshotPCRDigest(PCRSelection{Hash: AlgSHA256}, snapshot); err == nil {
		t.Error("snapshotPCRDigest() succeeded with an empty selection, want failure")
	}
}
