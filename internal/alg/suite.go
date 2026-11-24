package alg

import (
	"fmt"
	"strings"
)

const (
	AlgAES = "AES"
	AlgSM4 = "SM4"

	AlgIDAES = byte(0x01)
	AlgIDSM4 = byte(0x02)

	KDFArgon2id = "Argon2id"
	KDFPBKDF2   = "PBKDF2"

	KDFIDArgon2id = byte(0x01)
	KDFIDPBKDF2   = byte(0x02)

	DefaultSaltLen  = 16
	DefaultKeyLen   = 32
	DefaultNonceLen = 12
	DefaultTagLen   = 16
	DefaultMacLen   = 32
)

// Suite is the interface that encapsulates an encryption algorithm suite.
// It provides encrypt/decrypt with GCM mode and MAC computation.
type Suite interface {
	// Name returns the algorithm suite name ("AES" or "SM4").
	Name() string
	// ID returns the single-byte algorithm identifier.
	ID() byte

	// KeyLen returns the symmetric key length in bytes (32 for AES-256, 16 for SM4).
	// Useful for deriving keys that will be passed to EncryptGCM/DecryptGCM.
	KeyLen() int

	// EncryptGCM encrypts plaintext using GCM with the given key and AAD.
	// Returns ciphertext || tag (nonce must be supplied separately by caller).
	EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error)
	// DecryptGCM decrypts ciphertext produced by EncryptGCM.
	DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error)

	// ComputeMAC computes HMAC-SHA256 over data using key.
	ComputeMAC(key, data []byte) ([]byte, error)
	// VerifyMAC verifies HMAC-SHA256 over data using key.
	VerifyMAC(key, data, mac []byte) bool

	// GenerateNonce generates a random nonce suitable for GCM.
	GenerateNonce() ([]byte, error)
}

// NewSuite creates a Suite by algorithm name (case-insensitive, surrounding
// whitespace ignored).
func NewSuite(name string) (Suite, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "aes":
		return &AESSuite{}, nil
	case "sm4":
		return &SM4Suite{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", name)
	}
}

// NewSuiteByID creates a Suite by single-byte identifier.
func NewSuiteByID(id byte) (Suite, error) {
	switch id {
	case AlgIDAES:
		return &AESSuite{}, nil
	case AlgIDSM4:
		return &SM4Suite{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm ID: 0x%02x", id)
	}
}

// algNameByID returns the algorithm name for a single-byte id.
func AlgNameByID(id byte) string {
	switch id {
	case AlgIDAES:
		return AlgAES
	case AlgIDSM4:
		return AlgSM4
	default:
		return "Unknown"
	}
}

// kdfNameByID returns the KDF name for a single-byte id.
func KdfNameByID(id byte) string {
	switch id {
	case KDFIDArgon2id:
		return KDFArgon2id
	case KDFIDPBKDF2:
		return KDFPBKDF2
	default:
		return "Unknown"
	}
}
