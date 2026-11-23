package alg

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

// SM4Suite implements Suite using SM4 in GCM-like mode.
// Since pure SM4-GCM is not standardized in Go crypto, we use SM4-CTR + HMAC-SHA256
// as an AEAD construction which provides both confidentiality and integrity.
type SM4Suite struct{}

func (s *SM4Suite) Name() string { return AlgSM4 }
func (s *SM4Suite) ID() byte     { return AlgIDSM4 }
func (s *SM4Suite) KeyLen() int  { return sm4KeySize }

// sm4KeySize is the expected key length for SM4.
const sm4KeySize = 16

// sm4BlockSize is the block size of SM4.
const sm4BlockSize = 16

// EncryptGCM encrypts plaintext using SM4-CTR + HMAC-SHA256.
// Output: nonce(12) || ciphertext || tag(32)
func (s *SM4Suite) EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}
	if len(nonce) != DefaultNonceLen {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), DefaultNonceLen)
	}
	fullNonce := append([]byte{}, nonce...)
	ctr := cipher.NewCTR(block, fullNonce)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	dataForMAC := append([]byte{}, aad...)
	dataForMAC = append(dataForMAC, ciphertext...)
	tag := hmac.New(sha256.New, key)
	tag.Write(dataForMAC)
	macBytes := tag.Sum(nil)

	result := make([]byte, 0, DefaultNonceLen+len(ciphertext)+sha256.Size)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	result = append(result, macBytes...)
	return result, nil
}

// DecryptGCM decrypts ciphertext produced by EncryptGCM.
func (s *SM4Suite) DecryptGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	if len(ciphertext) < sha256.Size {
		return nil, fmt.Errorf("ciphertext too short for MAC tag")
	}
	tagPos := len(ciphertext) - sha256.Size
	actualCiphertext := ciphertext[:tagPos]
	expectedTag := ciphertext[tagPos:]

	dataForMAC := append([]byte{}, aad...)
	dataForMAC = append(dataForMAC, actualCiphertext...)
	mac := hmac.New(sha256.New, key)
	mac.Write(dataForMAC)
	if !hmac.Equal(mac.Sum(nil), expectedTag) {
		return nil, fmt.Errorf("SM4 MAC verification failed")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}
	if len(nonce) != DefaultNonceLen {
		return nil, fmt.Errorf("nonce size mismatch: got %d, need %d", len(nonce), DefaultNonceLen)
	}
	ctr := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(actualCiphertext))
	ctr.XORKeyStream(plaintext, actualCiphertext)
	return plaintext, nil
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

// GenerateNonce generates a random 12-byte nonce.
func (s *SM4Suite) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, DefaultNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}
