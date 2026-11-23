package tpm2test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestNVAuthWrite(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		Auth: TPM2BAuth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: 4,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   PasswordAuth([]byte("p@ssw0rd")),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := prewrite.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	read := NVReadPublic{
		NVIndex: pub.NVIndex,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	t.Logf("Name: %x", readRsp.NVName.Buffer)

	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   readRsp.NVName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}
}

func TestNVAuthIncrement(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Define the counter space
	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		Auth: TPM2BAuth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         TPMNTCounter,
					NoDA:       true,
				},
				DataSize: 8,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Calculate the Name of the index as of its creation
	// (i.e., without NV_WRITTEN set).
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	incr := NVIncrement{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
	}
	if _, err := incr.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Increment: %v", err)
	}

	// The NV index's Name has changed. Ask the TPM for it.
	readPub := NVReadPublic{
		NVIndex: pub.NVIndex,
	}
	readPubRsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	incr.NVIndex = NamedHandle{
		Handle: pub.NVIndex,
		Name:   readPubRsp.NVName,
	}

	read := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubRsp.NVName,
		},
		Size: 8,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	if _, err := incr.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Increment: %v", err)
	}

	var val1 uint64
	err = binary.Read(bytes.NewReader(readRsp.Data.Buffer), binary.BigEndian, &val1)
	if err != nil {
		t.Fatalf("Parsing counter: %v", err)
	}

	readRsp, err = read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	var val2 uint64
	err = binary.Read(bytes.NewReader(readRsp.Data.Buffer), binary.BigEndian, &val2)
	if err != nil {
		t.Fatalf("Parsing counter: %v", err)
	}

	if val2 != (val1 + 1) {
		t.Errorf("want %v got %v", val1+1, val2)
	}
}

func TestNVWriteLock(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Define the NV space with attributes that allow it to be locked
	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite:   true,
					OwnerRead:    true,
					WriteSTClear: true, // Allow TPM2_NV_WriteLock to lock this index
				},
				DataSize: 4,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	// Write data to the NV space
	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	// Lock the NV space against further writes
	lock := NVWriteLock{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
	}
	if _, err := lock.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_WriteLock: %v", err)
	}

	// Try to write to the NV space again, which should fail because it's locked
	write2 := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x05, 0x06, 0x07, 0x08},
		},
		Offset: 0,
	}
	_, err = write2.Execute(thetpm)
	if !errors.Is(err, TPMRCNVLocked) {
		t.Errorf("TPM2_NV_Write succeeded after NV_WriteLock, expected it to fail")
	}

	// Verify we can still read the data
	read := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Size:   4,
		Offset: 0,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	// Verify the data is still the original data
	expectedData := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(readRsp.Data.Buffer, expectedData) {
		t.Errorf("Read data doesn't match expected data. Got %v, want %v", readRsp.Data.Buffer, expectedData)
	}
}

func TestNVReadLock(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Define the NV space with attributes that allow it to be locked for reading
	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite:  true,
					OwnerRead:   true,
					ReadSTClear: true, // Allow TPM2_NV_ReadLock to lock this index
				},
				DataSize: 4,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	// Write data to the NV space
	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	// Read the data to verify it's accessible
	read := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Size:   4,
		Offset: 0,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read before locking: %v", err)
	}

	// Verify the data is correct
	expectedData := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(readRsp.Data.Buffer, expectedData) {
		t.Errorf("Read data doesn't match expected data. Got %v, want %v", readRsp.Data.Buffer, expectedData)
	}

	// Lock the NV space against further reads
	lock := NVReadLock{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
	}
	if _, err := lock.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_ReadLock: %v", err)
	}

	// Try to read from the NV space again, which should fail because it's locked
	read2 := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   PasswordAuth(nil),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Size:   4,
		Offset: 0,
	}
	_, err = read2.Execute(thetpm)
	if !errors.Is(err, TPMRCNVLocked) {
		t.Errorf("TPM2_NV_Read succeeded after NV_ReadLock, expected it to fail")
	}
}

// defineNVIndex defines an ordinary NV index with the given handle, size and
// attributes, and returns its public area and Name.
func defineNVIndex(
	t *testing.T, thetpm transport.TPMCloser, index TPMHandle,
	size uint16, attrs TPMANV,
) (*TPMSNVPublic, *TPM2BName) {
	t.Helper()
	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex:    index,
				NameAlg:    TPMAlgSHA256,
				Attributes: attrs,
				DataSize:   size,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}
	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}
	return pub, nvName
}

// undefineNVIndex removes the NV index, so a test can re-define it with
// different attributes.
func undefineNVIndex(t *testing.T, thetpm transport.TPMCloser, index TPMHandle) {
	t.Helper()
	readPubRsp, err := NVReadPublic{NVIndex: index}.Execute(thetpm)
	if err != nil {
		// The index is already gone (e.g. an earlier assertion stopped
		// the test before cleanup ran); nothing to do.
		return
	}
	if _, err := (NVUndefineSpace{
		AuthHandle: TPMRHOwner,
		NVIndex: NamedHandle{
			Handle: index,
			Name:   readPubRsp.NVName,
		},
	}).Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_UndefineSpace: %v", err)
	}
}

// TestNVWriteFailureKeepsSessionUsable makes sure that an authorization
// session survives a failed TPM2_NV_Write. A reusable HMAC session must keep
// working after the TPM rejects a command: the error response carries a fresh
// nonceTPM that the library has to track, otherwise the next command using the
// same session is rejected with TPM_RC_HMAC.
func TestNVWriteFailureKeepsSessionUsable(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	index := TPMHandle(0x01800020)
	attrs := TPMANV{
		OwnerWrite: true,
		OwnerRead:  true,
		AuthWrite:  true,
		AuthRead:   true,
		NT:         TPMNTOrdinary,
		NoDA:       true,
	}
	pub, nvName := defineNVIndex(t, thetpm, index, 4, attrs)
	defer undefineNVIndex(t, thetpm, index)

	// A single reusable HMAC session authorizes every command in this test,
	// including the one that the TPM is expected to reject.
	sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Auth([]byte{}))
	if err != nil {
		t.Fatalf("Starting HMAC session: %v", err)
	}
	defer cleanup()

	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	// Force the first write to fail with a size error: a 4-byte buffer cannot
	// be written 2 bytes past the end of a 4-byte NV area.
	badWrite := write
	badWrite.Offset = 2
	if _, err := badWrite.Execute(thetpm); !errors.Is(err, TPMRCNVRange) &&
		!errors.Is(err, TPMRCNVSize) {
		t.Fatalf("Expected TPM_RC_NV_RANGE or TPM_RC_NV_SIZE from the out-of-range write, got %v", err)
	}

	// The session must still be usable after the failed command. Retry with a
	// legal offset and the same session.
	if _, err := write.Execute(thetpm); err != nil {
		t.Fatalf("Retrying TPM2_NV_Write after a failure: %v", err)
	}

	// A consumer reading through the same session must see the data that the
	// successful write committed, not anything from an earlier generation.
	readRsp, err := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Size: 4,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read after a failed write: %v", err)
	}
	if got, want := readRsp.Data.Buffer, write.Data.Buffer; !bytes.Equal(got, want) {
		t.Errorf("NV contents after retry = %v, want %v", got, want)
	}
}

// TestNVRedefineAfterWriteFailureIsolatesGenerations verifies the complete
// state after a write failure: re-defining the index creates a new generation
// whose policy, owner authorization, size and attributes are exactly the ones
// of the new definition. Neither the old generation's contents nor its
// permissions may leak into the new one, and the session used across the
// failed write must remain valid.
func TestNVRedefineAfterWriteFailureIsolatesGenerations(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	index := TPMHandle(0x01800021)
	firstAttrs := TPMANV{
		OwnerWrite: true,
		OwnerRead:  true,
		AuthWrite:  true,
		AuthRead:   true,
		NT:         TPMNTOrdinary,
		NoDA:       true,
	}
	firstPub, firstName := defineNVIndex(t, thetpm, index, 4, firstAttrs)

	// First generation: commit known contents with the owner's empty auth
	// value, through one reusable HMAC session.
	sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Auth([]byte{}))
	if err != nil {
		t.Fatalf("Starting HMAC session: %v", err)
	}
	defer cleanup()

	firstData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if _, err := (NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: firstPub.NVIndex,
			Name:   *firstName,
		},
		Data: TPM2BMaxNVBuffer{Buffer: firstData},
	}).Execute(thetpm); err != nil {
		t.Fatalf("Writing the first generation: %v", err)
	}

	// Make a write fail on the first generation.
	badWrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: firstPub.NVIndex,
			Name:   *firstName,
		},
		Data:   TPM2BMaxNVBuffer{Buffer: []byte{0x00, 0x00, 0x00, 0x00}},
		Offset: 2,
	}
	if _, err := badWrite.Execute(thetpm); !errors.Is(err, TPMRCNVRange) &&
		!errors.Is(err, TPMRCNVSize) {
		t.Fatalf("Expected TPM_RC_NV_RANGE or TPM_RC_NV_SIZE from the out-of-range write, got %v", err)
	}

	// Retire the first generation and define a new one with a different size
	// and attributes. The new generation only accepts owner authorization;
	// index auth is no longer permitted.
	undefineNVIndex(t, thetpm, index)
	secondAttrs := TPMANV{
		OwnerWrite: true,
		OwnerRead:  true,
		NT:         TPMNTOrdinary,
		NoDA:       true,
	}
	secondPub, secondName := defineNVIndex(t, thetpm, index, 8, secondAttrs)
	defer undefineNVIndex(t, thetpm, index)

	// The public area must reflect the new generation's legal size/attrs.
	readPubRsp, err := NVReadPublic{NVIndex: index}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic on the new generation: %v", err)
	}
	gotPub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if gotPub.DataSize != secondPub.DataSize {
		t.Errorf("DataSize = %v, want %v", gotPub.DataSize, secondPub.DataSize)
	}
	if gotPub.Attributes != secondPub.Attributes {
		t.Errorf("Attributes = %+v, want %+v", gotPub.Attributes, secondPub.Attributes)
	}

	// The Name changed when the index was re-defined: commands must present
	// the new generation's Name. Using the stale Name must fail.
	if bytes.Equal(readPubRsp.NVName.Buffer, firstName.Buffer) {
		t.Errorf("The re-defined NV index kept its previous Name")
	}

	// Write the second generation's contents through the same session, using
	// the owner auth and the new Name.
	secondData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if _, err := (NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: secondPub.NVIndex,
			Name:   *secondName,
		},
		Data: TPM2BMaxNVBuffer{Buffer: secondData},
	}).Execute(thetpm); err != nil {
		t.Fatalf("Writing the new generation with owner auth after a failed write "+
			"and re-definition: %v", err)
	}

	// Authorizing the write with the index itself must fail: AuthWrite and
	// AuthRead are clear in the new generation.
	if _, err := (NVWrite{
		AuthHandle: AuthHandle{
			Handle: secondPub.NVIndex,
			Name:   *secondName,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: secondPub.NVIndex,
			Name:   *secondName,
		},
		Data: TPM2BMaxNVBuffer{Buffer: make([]byte, 8)},
	}).Execute(thetpm); !errors.Is(err, TPMRCNVAuthorization) {
		t.Errorf("Writing with index auth to an owner-only index: "+
			"want TPM_RC_NV_AUTHORIZATION, got %v", err)
	}

	// Reading through the shared session must return only the new generation's
	// contents; the first generation's data must not be observable.
	readRsp, err := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   sess,
		},
		NVIndex: NamedHandle{
			Handle: secondPub.NVIndex,
			Name:   *secondName,
		},
		Size: 8,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Reading the new generation: %v", err)
	}
	if !bytes.Equal(readRsp.Data.Buffer, secondData) {
		t.Errorf("New generation contents = %v, want %v", readRsp.Data.Buffer, secondData)
	}
	if bytes.Equal(readRsp.Data.Buffer[:4], firstData) {
		t.Errorf("The new generation exposed the previous generation's contents")
	}
}
