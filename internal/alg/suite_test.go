package alg

import (
	"bytes"
	"testing"
)

// allSuites returns both suites as table-driven test targets.
func allSuites() []Suite {
	return []Suite{&AESSuite{}, &SM4Suite{}}
}

// TestSuiteMetadata verifies Name/ID/KeyLen are consistent across both suites.
func TestSuiteMetadata(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			if s.Name() != AlgAES && s.Name() != AlgSM4 {
				t.Errorf("unexpected name: %s", s.Name())
			}
			if s.ID() != AlgIDAES && s.ID() != AlgIDSM4 {
				t.Errorf("unexpected ID: 0x%02x", s.ID())
			}
			if s.KeyLen() != 32 && s.KeyLen() != 16 {
				t.Errorf("unexpected key length: %d", s.KeyLen())
			}
		})
	}
}

// TestEncryptDecryptRoundtrip verifies ciphertext produced by EncryptGCM is
// correctly recovered by DecryptGCM with the same key/nonce/aad.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	plaintexts := [][]byte{
		nil,                         // empty
		[]byte("hello, world"),      // short
		make([]byte, 1024),          // 1 KB
		[]byte("中文 / ê / \x00\xff"), // unicode + binary
	}
	aads := [][]byte{nil, []byte("aad-123"), []byte("")}

	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			key := make([]byte, s.KeyLen())
			nonce, err := s.GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce: %v", err)
			}

			for _, pt := range plaintexts {
				for _, aad := range aads {
					ct, err := s.EncryptGCM(key, nonce, pt, aad)
					if err != nil {
						t.Fatalf("EncryptGCM(pt=%d, aad=%d): %v", len(pt), len(aad), err)
					}
					got, err := s.DecryptGCM(key, nonce, ct, aad)
					if err != nil {
						t.Fatalf("DecryptGCM: %v", err)
					}
					if !bytes.Equal(got, pt) {
						t.Errorf("roundtrip mismatch: got %x want %x", got, pt)
					}
				}
			}
		})
	}
}

// TestEncryptDecryptTamper verifies GCM's authentication: tampered ciphertext,
// wrong AAD, or wrong key all fail decryption.
func TestEncryptDecryptTamper(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			key := make([]byte, s.KeyLen())
			nonce, _ := s.GenerateNonce()
			pt := []byte("secret message")
			aad := []byte("meta")

			ct, err := s.EncryptGCM(key, nonce, pt, aad)
			if err != nil {
				t.Fatal(err)
			}

			// 1. Flip a bit in ciphertext (first ct byte before tag)
			tampered := append([]byte{}, ct...)
			tampered[0] ^= 0x01
			if _, err := s.DecryptGCM(key, nonce, tampered, aad); err == nil {
				t.Error("expected error on tampered ciphertext, got nil")
			}

			// 2. Wrong AAD
			if _, err := s.DecryptGCM(key, nonce, ct, []byte("wrong")); err == nil {
				t.Error("expected error on wrong AAD, got nil")
			}

			// 3. Wrong key
			badKey := make([]byte, s.KeyLen())
			badKey[0] = 0xFF
			if _, err := s.DecryptGCM(badKey, nonce, ct, aad); err == nil {
				t.Error("expected error on wrong key, got nil")
			}

			// 4. Wrong nonce
			badNonce := make([]byte, len(nonce))
			badNonce[0] = 0xFF
			if _, err := s.DecryptGCM(key, badNonce, ct, aad); err == nil {
				t.Error("expected error on wrong nonce, got nil")
			}
		})
	}
}

// TestEncryptDecryptKeyLengthErrors verifies that wrong key/nonce lengths are rejected.
func TestEncryptDecryptKeyLengthErrors(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			badKey := make([]byte, s.KeyLen()+1)
			goodKey := make([]byte, s.KeyLen())
			badNonce := make([]byte, DefaultNonceLen-1)
			goodNonce, _ := s.GenerateNonce()

			if _, err := s.EncryptGCM(badKey, goodNonce, []byte("x"), nil); err == nil {
				t.Error("expected error on wrong key length")
			}
			if _, err := s.EncryptGCM(goodKey, badNonce, []byte("x"), nil); err == nil {
				t.Error("expected error on wrong nonce length")
			}
			if _, err := s.DecryptGCM(badKey, goodNonce, []byte("short"), nil); err == nil {
				t.Error("expected error on wrong key length (decrypt)")
			}
		})
	}
}

// TestMACRoundtrip verifies ComputeMAC + VerifyMAC agreement.
func TestMACRoundtrip(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			key := make([]byte, 32)
			data := []byte("some data")

			mac, err := s.ComputeMAC(key, data)
			if err != nil {
				t.Fatalf("ComputeMAC: %v", err)
			}
			if len(mac) != DefaultMacLen {
				t.Errorf("MAC length = %d, want %d", len(mac), DefaultMacLen)
			}
			if !s.VerifyMAC(key, data, mac) {
				t.Error("VerifyMAC should accept valid MAC")
			}
			if s.VerifyMAC(key, []byte("other"), mac) {
				t.Error("VerifyMAC should reject wrong data")
			}
			mac[0] ^= 0x01
			if s.VerifyMAC(key, data, mac) {
				t.Error("VerifyMAC should reject tampered MAC")
			}
		})
	}
}

// TestMACEmptyKey verifies empty MAC key is rejected.
func TestMACEmptyKey(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			if _, err := s.ComputeMAC(nil, []byte("x")); err == nil {
				t.Error("expected error on nil key")
			}
			if _, err := s.ComputeMAC([]byte{}, []byte("x")); err == nil {
				t.Error("expected error on empty key")
			}
		})
	}
}

// TestGenerateNonceUniqueness verifies GenerateNonce produces distinct values
// across many calls (collision probability is astronomically low for 12 bytes).
func TestGenerateNonceUniqueness(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			seen := make(map[string]bool, 1000)
			for i := 0; i < 1000; i++ {
				n, err := s.GenerateNonce()
				if err != nil {
					t.Fatal(err)
				}
				if len(n) != DefaultNonceLen {
					t.Errorf("nonce len = %d, want %d", len(n), DefaultNonceLen)
				}
				k := string(n)
				if seen[k] {
					t.Fatal("duplicate nonce generated — crypto/rand is broken")
				}
				seen[k] = true
			}
		})
	}
}

// TestNewSuiteByNameAndID verifies constructor functions.
func TestNewSuiteByNameAndID(t *testing.T) {
	cases := []struct {
		name string
		id   byte
	}{
		{AlgAES, AlgIDAES},
		{AlgSM4, AlgIDSM4},
	}
	for _, c := range cases {
		s1, err := NewSuite(c.name)
		if err != nil {
			t.Fatalf("NewSuite(%q): %v", c.name, err)
		}
		s2, err := NewSuiteByID(c.id)
		if err != nil {
			t.Fatalf("NewSuiteByID(0x%02x): %v", c.id, err)
		}
		if s1.ID() != s2.ID() {
			t.Errorf("NewSuite and NewSuiteByID returned different IDs for %s", c.name)
		}
	}

	if _, err := NewSuite("unknown"); err == nil {
		t.Error("expected error for unknown suite name")
	}
	if _, err := NewSuiteByID(0xFF); err == nil {
		t.Error("expected error for unknown suite ID")
	}
}

// TestEncryptDecryptDeterminism verifies EncryptGCM is NOT deterministic given
// the same key/nonce/pt/aad — GCM's internal counter (or in our case the lack
// of nonce reuse protection) doesn't matter here, but we DO verify the
// ciphertext length equals pt + tagLen.
func TestEncryptDecryptOutputLength(t *testing.T) {
	for _, s := range allSuites() {
		t.Run(s.Name(), func(t *testing.T) {
			key := make([]byte, s.KeyLen())
			nonce, _ := s.GenerateNonce()
			pt := []byte("exactly 16 bytes") // 16 bytes
			ct, err := s.EncryptGCM(key, nonce, pt, nil)
			if err != nil {
				t.Fatal(err)
			}
			wantLen := len(pt) + DefaultTagLen
			if len(ct) != wantLen {
				t.Errorf("ciphertext len = %d, want %d (pt=%d + tag=%d)",
					len(ct), wantLen, len(pt), DefaultTagLen)
			}
		})
	}
}
