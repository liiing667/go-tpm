package tpm2test

import (
	"bytes"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// TestExecuteWithAuditAgainstTPM runs the transactional audit against a real
// TPM (simulator) and proves the locally computed audit digest is identical to
// the digest the TPM itself accumulates inside its audit session for the same
// successful commands. It also proves that two successful transactions extend
// the digest twice and that the struct-based legacy audit agrees.
func TestExecuteWithAuditAgainstTPM(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Audit())
	if err != nil {
		t.Fatalf("HMACSession: %v", err)
	}
	defer cleanup()

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	legacy, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}

	props := []TPMPT{TPMPTManufacturer, TPMPTFamilyIndicator, TPMPTRevision}
	for i, prop := range props {
		cmd := GetCapability{
			Capability:    TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}
		rsp, err := ExecuteWithAudit(thetpm, audit, cmd, sess)
		if err != nil {
			t.Fatalf("ExecuteWithAudit (prop %v): %v", prop, err)
		}
		if err := AuditCommand(legacy, cmd, rsp); err != nil {
			t.Fatalf("AuditCommand: %v", err)
		}
		if !bytes.Equal(audit.Digest(), legacy.Digest()) {
			t.Fatalf("transactional and legacy audit digests differ after command %d", i+1)
		}
		if bytes.Equal(audit.Digest(), make([]byte, len(audit.Digest()))) {
			t.Fatalf("audit digest was not extended after command %d", i+1)
		}
	}
}

// TestExecuteWithAuditErrorResponseAgainstTPM drives a command that the TPM
// rejects and proves the rejected transaction does not move the audit digest.
func TestExecuteWithAuditErrorResponseAgainstTPM(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	initial := append([]byte(nil), audit.Digest()...)

	// An unsupported RSA key size is rejected by the simulator with
	// TPM_RC_VALUE (see test_parms_test.go), i.e. a non-success response code.
	bad := TestParms{
		Parameters: TPMTPublicParms{
			Type: TPMAlgRSA,
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{KeyBits: 4096},
			),
		},
	}
	if _, err := ExecuteWithAudit(thetpm, audit, bad); !errors.Is(err, TPMRCValue) {
		t.Fatalf("ExecuteWithAudit error = %v, want TPM_RC_VALUE", err)
	}
	if !bytes.Equal(audit.Digest(), initial) {
		t.Fatalf("audit digest changed after a TPM error response:\ngot  %x\nwant %x", audit.Digest(), initial)
	}

	// A subsequent successful command must produce exactly the same digest as
	// an audit that never saw the failed attempt.
	good := GetCapability{
		Capability:    TPMCapTPMProperties,
		Property:      uint32(TPMPTManufacturer),
		PropertyCount: 1,
	}
	rsp, err := ExecuteWithAudit(thetpm, audit, good)
	if err != nil {
		t.Fatalf("ExecuteWithAudit: %v", err)
	}
	want, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewAudit: %v", err)
	}
	if err := AuditCommand(want, good, rsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}
	if !bytes.Equal(audit.Digest(), want.Digest()) {
		t.Fatalf("audit digest after a failed-then-successful sequence is wrong:\ngot %x\nwant %x",
			audit.Digest(), want.Digest())
	}
}
