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
type KDFParams struct {
	Name string
	ID   byte
	M    uint32
	T    byte
	P    byte
	Salt []byte
}

// DefaultKDFParams returns the default Argon2id parameters.
func DefaultKDFParams() KDFParams {
	salt := make([]byte, DefaultSaltLen)
	_, _ = rand.Read(salt)
	return KDFParams{
		Name: KDFArgon2id,
		ID:   KDFIDArgon2id,
		M:    64,
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
		return KDFParams{Name: KDFArgon2id, ID: KDFIDArgon2id, M: 64, T: 3, P: 2, Salt: salt}, nil
	case "pbkdf2":
		return KDFParams{Name: KDFPBKDF2, ID: KDFIDPBKDF2, M: 32, T: 100, P: 1, Salt: salt}, nil
	default:
		return KDFParams{}, fmt.Errorf("unsupported KDF: %s", name)
	}
}

// NewKDFParamsByID creates KDFParams by single-byte identifier with a fresh salt.
func NewKDFParamsByID(id byte) (KDFParams, error) {
	switch id {
	case KDFIDArgon2id:
		return NewKDFParams(KDFArgon2id)
	case KDFIDPBKDF2:
		return NewKDFParams(KDFPBKDF2)
	default:
		return KDFParams{}, fmt.Errorf("unsupported KDF ID: 0x%02x", id)
	}
}

// Derive derives a key of given length from passphrase using this KDF.
func (p KDFParams) Derive(passphrase string, keyLen uint32) ([]byte, error) {
	if len(p.Salt) == 0 {
		return nil, fmt.Errorf("salt is empty")
	}
	switch p.ID {
	case KDFIDArgon2id:
		return argon2.IDKey([]byte(passphrase), p.Salt, uint32(p.M), uint32(p.T), uint8(p.P), keyLen), nil
	case KDFIDPBKDF2:
		iters := uint32(p.M)*100 + uint32(p.T)
		if iters < 1000 {
			iters = 1000
		}
		return pbkdf2.Key([]byte(passphrase), p.Salt, int(iters), int(keyLen), sha256.New), nil
	default:
		return nil, fmt.Errorf("unsupported KDF ID: 0x%02x", p.ID)
	}
}

// DeriveRootKey derives a root key from master passphrase.
func DeriveRootKey(passphrase string, params KDFParams) ([]byte, error) {
	return params.Derive(passphrase, DefaultKeyLen)
}

// DeriveInfoKey derives an info key from secondary passphrase.
func DeriveInfoKey(passphrase string, params KDFParams) ([]byte, error) {
	return params.Derive(passphrase, DefaultKeyLen)
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
