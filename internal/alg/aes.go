package alg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// AESSuite implements Suite using AES-256-GCM.
type AESSuite struct{}

func (a *AESSuite) Name() string { return AlgAES }
func (a *AESSuite) ID() byte     { return AlgIDAES }
func (a *AESSuite) KeyLen() int  { return 32 }

// EncryptGCM encrypts plaintext using AES-256-GCM.
func (a *AESSuite) EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), gcm.NonceSize())
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// DecryptGCM decrypts ciphertext produced by EncryptGCM.
func (a *AESSuite) DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// ComputeMAC computes HMAC-SHA256 over data using key.
func (a *AESSuite) ComputeMAC(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("MAC key is empty")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyMAC verifies HMAC-SHA256 over data using key.
func (a *AESSuite) VerifyMAC(key, data, expected []byte) bool {
	got, err := a.ComputeMAC(key, data)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// GenerateNonce generates a random 12-byte nonce.
func (a *AESSuite) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, DefaultNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}
