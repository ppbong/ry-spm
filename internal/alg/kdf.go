package alg

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KDFParams holds the parameters for a key derivation function.
//
// For Argon2id (OWASP 2024 recommended):
//
//	M = memory in MB     (≥ 128)
//	T = time factor      (≥ 3)
//	P = parallelism      (2 on modern CPUs)
//
// For PBKDF2-HMAC-SHA256:
//
//	M = iteration count  (≥ 600_000 per OWASP 2024)
//	T, P are ignored.
type KDFParams struct {
	Name string
	ID   byte
	M    uint32
	T    byte
	P    byte
	Salt []byte
}

// DefaultKDFParams returns the default Argon2id parameters (128 MB / 3 / 2).
func DefaultKDFParams() KDFParams {
	salt := make([]byte, DefaultSaltLen)
	_, _ = rand.Read(salt)
	return KDFParams{
		Name: KDFArgon2id,
		ID:   KDFIDArgon2id,
		M:    128,
		T:    3,
		P:    2,
		Salt: salt,
	}
}

// NewKDFParams creates KDFParams by name with a fresh salt.
func NewKDFParams(name string) (KDFParams, error) {
	salt := make([]byte, DefaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("failed to generate salt: %w", err)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "", "argon2id", "argon2":
		// 128 MB memory is the OWASP-recommended floor for 2024 hardware
		return KDFParams{Name: KDFArgon2id, ID: KDFIDArgon2id, M: 128, T: 3, P: 2, Salt: salt}, nil
	case "pbkdf2":
		// 600_000 iterations is OWASP 2024 recommendation for PBKDF2-HMAC-SHA256
		return KDFParams{Name: KDFPBKDF2, ID: KDFIDPBKDF2, M: 600_000, T: 0, P: 0, Salt: salt}, nil
	default:
		return KDFParams{}, fmt.Errorf("unsupported KDF: %s", name)
	}
}

// Parameter bounds accepted when reading KDF settings from a vault header.
// They are deliberately generous compared with the defaults but stop crafted
// headers from panicking argon2 or exhausting memory/CPU before MAC checks.
const (
	MinArgon2MemoryMiB = 8
	MaxArgon2MemoryMiB = 1024
	MaxArgon2Time      = 10
	MaxArgon2Parallel  = 16
	MinPBKDF2Iter      = 10_000
	MaxPBKDF2Iter      = 10_000_000
)

// validate checks that the parameters are within supported bounds.
func (p KDFParams) validate() error {
	if len(p.Salt) == 0 {
		return fmt.Errorf("salt is empty")
	}
	switch p.ID {
	case KDFIDArgon2id:
		if p.M < MinArgon2MemoryMiB || p.M > MaxArgon2MemoryMiB {
			return fmt.Errorf("unsupported argon2id memory cost: %d MiB (allowed %d..%d)",
				p.M, MinArgon2MemoryMiB, MaxArgon2MemoryMiB)
		}
		if p.T < 1 || p.T > MaxArgon2Time {
			return fmt.Errorf("unsupported argon2id time cost: %d (allowed 1..%d)", p.T, MaxArgon2Time)
		}
		if p.P < 1 || p.P > MaxArgon2Parallel {
			return fmt.Errorf("unsupported argon2id parallelism: %d (allowed 1..%d)", p.P, MaxArgon2Parallel)
		}
	case KDFIDPBKDF2:
		if p.M < MinPBKDF2Iter || p.M > MaxPBKDF2Iter {
			return fmt.Errorf("unsupported PBKDF2 iteration count: %d (allowed %d..%d)",
				p.M, MinPBKDF2Iter, MaxPBKDF2Iter)
		}
	default:
		return fmt.Errorf("unsupported KDF ID: 0x%02x", p.ID)
	}
	return nil
}

// Derive derives a key of given length from passphrase using this KDF.
func (p KDFParams) Derive(passphrase string, keyLen uint32) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	switch p.ID {
	case KDFIDArgon2id:
		// M is stored in MB, argon2 library expects KiB
		return argon2.IDKey([]byte(passphrase), p.Salt, uint32(p.M)*1024, uint32(p.T), uint8(p.P), keyLen), nil
	case KDFIDPBKDF2:
		// M stores iteration count directly
		return pbkdf2.Key([]byte(passphrase), p.Salt, int(p.M), int(keyLen), sha256.New), nil
	default:
		return nil, fmt.Errorf("unsupported KDF ID: 0x%02x", p.ID)
	}
}

// DeriveRootKey derives a root key from master passphrase.
func DeriveRootKey(passphrase string, params KDFParams) ([]byte, error) {
	return params.Derive(passphrase, DefaultKeyLen)
}

// DeriveInfoKey derives the info-key from the root key via domain-separated sub-key derivation.
// The info-key protects vault metadata (category, labels) — it must not share the same
// derivation path as dataKey or macKey.
func DeriveInfoKey(rootKey []byte) ([]byte, error) {
	return DeriveSubKey(rootKey, "info-key", DefaultKeyLen)
}

// DeriveSubKey derives a sub-key from parent key using HKDF-like construction.
// info is optional context information for domain separation.
func DeriveSubKey(parentKey []byte, info string, keyLen uint32) ([]byte, error) {
	if len(parentKey) == 0 {
		return nil, fmt.Errorf("parent key is empty")
	}
	h := sha256.New()
	h.Write(parentKey)
	h.Write([]byte{byte(keyLen)})
	if info != "" {
		h.Write([]byte(info))
	}
	// Repeat hash to generate enough material
	var result []byte
	var counter byte
	for uint32(len(result)) < keyLen {
		h.Reset()
		h.Write(parentKey)
		h.Write([]byte{counter})
		if info != "" {
			h.Write([]byte(info))
		}
		result = append(result, h.Sum(nil)...)
		counter++
		if counter == 0 {
			return nil, fmt.Errorf("sub-key derivation overflow")
		}
	}
	return result[:keyLen], nil
}

// DeriveDataKey derives the data encryption key from the root key.
func DeriveDataKey(rootKey []byte) ([]byte, error) {
	return DeriveSubKey(rootKey, "data-key", DefaultKeyLen)
}

// DeriveMacKey derives the MAC signing key from the root key.
func DeriveMacKey(rootKey []byte) ([]byte, error) {
	return DeriveSubKey(rootKey, "mac-key", DefaultMacLen)
}

// DeriveChunkKey derives a per-block key from dataKey + "chunk-<seq>" label.
func DeriveChunkKey(dataKey []byte, seq uint16) ([]byte, error) {
	info := fmt.Sprintf("chunk-%d", seq)
	return DeriveSubKey(dataKey, info, DefaultKeyLen)
}
