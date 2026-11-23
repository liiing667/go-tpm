package tpm2

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/google/go-tpm/tpm2/transport"
)

// CommandAudit represents an audit session for attesting the execution of a
// series of commands in the TPM. It is useful for both command and session
// auditing.
type CommandAudit struct {
	hash   TPMIAlgHash
	digest []byte
}

// NewAudit initializes a new CommandAudit with the specified hash algorithm.
func NewAudit(hash TPMIAlgHash) (*CommandAudit, error) {
	h, err := hash.Hash()
	if err != nil {
		return nil, err
	}
	return &CommandAudit{
		hash:   hash,
		digest: make([]byte, h.Size()),
	}, nil
}

// AuditCommand extends the audit digest with the given command and response.
// Go Generics do not allow type parameters on methods, otherwise this would be
// a method on CommandAudit.
// See https://github.com/golang/go/issues/49085 for more information.
//
// AuditCommand is retained for compatibility with existing audit logs: it
// audits a command and a successful response independently of how they were
// obtained. To make sure the audited command, response code and caller-visible
// error can never disagree (for example because a warning response was
// retried), prefer [ExecuteWithAudit], which only reaches the audit after a
// fully successful execution.
func AuditCommand[C Command[R, *R], R any](a *CommandAudit, cmd C, rsp *R) error {
	cc := cmd.Command()
	cpHash, err := auditCPHash[R](cc, a.hash, cmd)
	if err != nil {
		return err
	}
	rpHash, err := auditRPHash(cc, a.hash, rsp)
	if err != nil {
		return err
	}
	return a.extend(cpHash, rpHash)
}

// Digest returns the current digest of the audit.
func (a *CommandAudit) Digest() []byte {
	return a.digest
}

// ExecuteWithAudit runs cmd against t as a single audited transaction and,
// only if the whole transaction succeeds, extends a's digest with that
// transaction. The command input, the TPM response code, the audit digest and
// the error returned to the caller therefore all describe one execution:
//
//   - If the TPM returns a warning (such as TPM_RC_RETRY) or any other
//     non-success response code, execution fails, the response is not parsed
//     into the success response and the digest is left untouched. A caller
//     that retries by calling ExecuteWithAudit again can never extend the
//     digest with the warning response; only the final successful response is
//     audited, exactly once.
//   - If a session fails to initialize, sending the command fails, or the
//     response cannot be parsed or validated, the error is returned and the
//     digest is left untouched (this covers session errors and short
//     responses).
//   - The digest extension is committed atomically: if hashing fails for any
//     reason, the digest keeps its previous value and the audit failure is
//     returned as an error instead of being silently counted as a successful
//     audit.
//
// On success the returned response and the extension of the audit digest come
// from the same execution, so the digest can only ever summarize transactions
// the caller actually observed as successful.
func ExecuteWithAudit[C Command[R, *R], R any](t transport.TPM, a *CommandAudit, cmd C, sess ...Session) (*R, error) {
	var rsp R
	err, _, _, info := executeWithRaw[R](t, cmd, &rsp, sess...)
	if err != nil {
		// A warning, a retried attempt, a session/transport error or a
		// response that failed validation is not a successful transaction:
		// the audit digest must not move.
		return nil, err
	}
	// executeWithRaw only returns audit info together with a nil error, and
	// rspHeader guarantees that nil error means TPM_RC_SUCCESS. The cpHash
	// and rpHash preimages are the exact ones of that same transaction
	// (including any session-encrypted parameters, in their unencrypted
	// form), so the digest can never describe a different execution.
	if err := a.auditTransaction(info); err != nil {
		return nil, fmt.Errorf("auditing %v command: %w", cmd.Command(), err)
	}
	return &rsp, nil
}

// auditTransaction extends the digest with one fully successful execution,
// using the cpHash/rpHash preimages captured from that execution. It is the
// single commit point of ExecuteWithAudit: extend() writes the new digest
// atomically, so a hashing failure leaves the previous summary intact.
func (a *CommandAudit) auditTransaction(info *commandAuditInfo) error {
	if info == nil {
		return fmt.Errorf("missing audit information for executed transaction")
	}
	if info.rc != TPMRCSuccess {
		// Defense in depth: an error response must never reach the
		// success-only audit summary.
		return fmt.Errorf("refusing to audit response with code %v", info.rc)
	}
	cp, err := cpHash(a.hash, info.cc, info.names, info.cmdParms)
	if err != nil {
		return err
	}
	rp, err := rpHash(a.hash, info.rc, info.cc, info.rspParms)
	if err != nil {
		return err
	}
	return a.extend(cp, rp)
}

// extend folds one cpHash/rpHash pair into the running digest. The new digest
// is computed from a copy of the current digest, so a hashing error leaves the
// audit summary exactly where it was before the command.
func (a *CommandAudit) extend(cpHash, rpHash []byte) error {
	ha, err := a.hash.Hash()
	if err != nil {
		return err
	}
	previous := make([]byte, len(a.digest))
	copy(previous, a.digest)
	h := ha.New()
	h.Write(previous)
	h.Write(cpHash)
	h.Write(rpHash)
	a.digest = h.Sum(nil)
	return nil
}

// auditCPHash calculates the command parameter hash for a given command with
// the given hash algorithm. The command is assumed to not have any decrypt
// sessions.
func auditCPHash[R any](cc TPMCC, h TPMIAlgHash, c Command[R, *R]) ([]byte, error) {
	names, err := cmdNames(c)
	if err != nil {
		return nil, err
	}
	parms, err := cmdParameters(c, nil)
	if err != nil {
		return nil, err
	}
	return cpHash(h, cc, names, parms)
}

// auditRPHash calculates the response parameter hash for a given response with
// the given hash algorithm. The command is assumed to be successful and to not
// have any encrypt sessions.
func auditRPHash(cc TPMCC, h TPMIAlgHash, r any) ([]byte, error) {
	var parms bytes.Buffer
	parameters := taggedMembers(reflect.ValueOf(r).Elem(), "handle", true)
	for i, parameter := range parameters {
		if err := marshal(&parms, parameter); err != nil {
			return nil, fmt.Errorf("marshalling parameter %v: %w", i+1, err)
		}
	}
	return rpHash(h, TPMRCSuccess, cc, parms.Bytes())
}
