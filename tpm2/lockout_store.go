package tpm2

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	lockoutStateVersion   uint32 = 1
	maxLockoutStateSize          = 1 << 20
)

// LockoutStore is the durable backing store for LockoutState.
//
// Load must return ErrNoLockoutState when nothing has been committed. Save
// must publish the complete byte slice atomically: if Save returns an error,
// a subsequent Load must observe the previously committed state, not a
// partially written update.
//
// The store does not serialize Lockout operations. A single Lockout must be
// shared by concurrent callers for a given store.
type LockoutStore interface {
	Load() ([]byte, error)
	Save([]byte) error
}

var (
	_ LockoutStore = (*MemoryLockoutStore)(nil)
	_ LockoutStore = (*FileLockoutStore)(nil)
)

// MemoryLockoutStore is an in-memory LockoutStore. It is useful when the
// caller has a separate durability layer and for deterministic tests.
type MemoryLockoutStore struct {
	mu   sync.Mutex
	data []byte
}

// NewMemoryLockoutStore returns an empty in-memory store.
func NewMemoryLockoutStore() *MemoryLockoutStore {
	return &MemoryLockoutStore{}
}

// Load implements LockoutStore.
func (s *MemoryLockoutStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil, ErrNoLockoutState
	}
	return append([]byte(nil), s.data...), nil
}

// Save implements LockoutStore.
func (s *MemoryLockoutStore) Save(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]byte(nil), data...)
	return nil
}

// Bytes returns the currently persisted bytes. It is intended for diagnostics
// and tests.
func (s *MemoryLockoutStore) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data...)
}

// FileLockoutStore stores lockout state in a single file. Saves use a
// write-to-temporary-file, fsync, and rename sequence so readers observe either
// the complete old state or the complete new state.
//
// FileLockoutStore is safe for concurrent use by goroutines in one process. It
// does not coordinate separate processes that share the same path; callers
// should give one Lockout instance ownership of the file.
type FileLockoutStore struct {
	mu   sync.Mutex
	path string
}

// NewFileLockoutStore returns a file-backed LockoutStore.
func NewFileLockoutStore(path string) (*FileLockoutStore, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty lockout state path", ErrInvalidLockoutParameters)
	}
	return &FileLockoutStore{path: path}, nil
}

// Load implements LockoutStore.
func (s *FileLockoutStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoLockoutState
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxLockoutStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLockoutStateSize {
		return nil, fmt.Errorf("%w: state file exceeds %d bytes",
			ErrLockoutStateCorrupt, maxLockoutStateSize)
	}
	return data, nil
}

// Save implements LockoutStore.
func (s *FileLockoutStore) Save(data []byte) error {
	if len(data) > maxLockoutStateSize {
		return fmt.Errorf("%w: state is %d bytes, maximum is %d",
			ErrInvalidLockoutState, len(data), maxLockoutStateSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	written, err := tmp.Write(data)
	if err != nil {
		tmp.Close()
		return err
	}
	if written != len(data) {
		tmp.Close()
		return fmt.Errorf("%w: short write: wrote %d of %d bytes",
			ErrLockoutPersistence, written, len(data))
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}

	// Best-effort directory sync. The rename has already published either the
	// old or new complete file; a failed directory sync must not make the
	// in-memory transaction believe the save failed.
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

type lockoutDiskState struct {
	Version  uint32       `json:"version"`
	State    LockoutState `json:"state"`
	Checksum string       `json:"checksum"`
}

func encodeLockoutState(state LockoutState) ([]byte, error) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(stateBytes)
	disk := lockoutDiskState{
		Version:  lockoutStateVersion,
		State:    state,
		Checksum: hex.EncodeToString(sum[:]),
	}
	return json.Marshal(disk)
}

func decodeLockoutState(data []byte) (LockoutState, error) {
	if len(data) == 0 {
		return LockoutState{}, fmt.Errorf("%w: empty state", ErrLockoutStateCorrupt)
	}
	if len(data) > maxLockoutStateSize {
		return LockoutState{}, fmt.Errorf(
			"%w: state is %d bytes, maximum is %d",
			ErrLockoutStateCorrupt, len(data), maxLockoutStateSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var disk lockoutDiskState
	if err := decoder.Decode(&disk); err != nil {
		return LockoutState{}, fmt.Errorf("%w: decoding state: %v", ErrLockoutStateCorrupt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return LockoutState{}, fmt.Errorf("%w: trailing data after state", ErrLockoutStateCorrupt)
	}
	if disk.Version != lockoutStateVersion {
		return LockoutState{}, fmt.Errorf(
			"%w: unsupported state version %d, want %d",
			ErrLockoutStateCorrupt, disk.Version, lockoutStateVersion)
	}

	stateBytes, err := json.Marshal(disk.State)
	if err != nil {
		return LockoutState{}, fmt.Errorf("%w: re-encoding state: %v", ErrLockoutStateCorrupt, err)
	}
	expected := sha256.Sum256(stateBytes)
	checksum, err := hex.DecodeString(disk.Checksum)
	if err != nil || len(checksum) != sha256.Size {
		return LockoutState{}, fmt.Errorf("%w: invalid checksum encoding", ErrLockoutStateCorrupt)
	}
	if subtle.ConstantTimeCompare(checksum, expected[:]) != 1 {
		return LockoutState{}, fmt.Errorf("%w: checksum mismatch", ErrLockoutStateCorrupt)
	}
	return disk.State, nil
}
