package alg

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

// SM4Suite implements Suite using SM4-GCM.
// SM4's block interface satisfies crypto/cipher.Block, so it plugs directly
// into the standard cipher.NewGCM constructor for a true AEAD construction.
type SM4Suite struct{}

func (s *SM4Suite) Name() string { return AlgSM4 }
func (s *SM4Suite) ID() byte     { return AlgIDSM4 }
func (s *SM4Suite) KeyLen() int  { return 16 }

// EncryptGCM encrypts plaintext using SM4-GCM.
// Output: ciphertext || tag(16). Nonce is supplied separately by the caller.
func (s *SM4Suite) EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4-GCM: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// DecryptGCM decrypts ciphertext produced by EncryptGCM.
func (s *SM4Suite) DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4-GCM: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// ComputeMAC computes HMAC-SHA256 over data using key.
func (s *SM4Suite) ComputeMAC(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("MAC key is empty")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyMAC verifies HMAC-SHA256 over data using key.
func (s *SM4Suite) VerifyMAC(key, data, expected []byte) bool {
	got, err := s.ComputeMAC(key, data)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// GenerateNonce generates a random 12-byte nonce suitable for GCM.
func (s *SM4Suite) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, DefaultNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}
