package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppbong/ry-spm/internal/alg"
)

func TestRoundtrip(t *testing.T) {
	pass := "master1234"
	category := "email"
	name := "testroundtrip"

	err := Initialize("AES", category, name, pass, "PBKDF2")
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault after init: %v", err)
	}
	if h.Header.AlgId != alg.AlgIDAES {
		t.Errorf("AlgId = 0x%02x, want 0x%02x", h.Header.AlgId, alg.AlgIDAES)
	}
	if h.Base.Category != category {
		t.Errorf("Category = %q, want %q", h.Base.Category, category)
	}

	h.Header.LastUsedAt = "2025-01-01 00:00:00"
	h.Header.UpdatedAt = "2025-01-01 00:00:00"
	if err := saveVault(h); err != nil {
		t.Fatalf("saveVault: %v", err)
	}

	// Reload with correct passphrase — must round-trip the header changes.
	h2, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault after save: %v", err)
	}
	if h2.Header.LastUsedAt != h.Header.LastUsedAt {
		t.Errorf("LastUsedAt = %q, want %q", h2.Header.LastUsedAt, h.Header.LastUsedAt)
	}
	if h2.Header.UpdatedAt != h.Header.UpdatedAt {
		t.Errorf("UpdatedAt = %q, want %q", h2.Header.UpdatedAt, h.Header.UpdatedAt)
	}

	// Atomic write should not leave stray temp files.
	matches, _ := filepath.Glob(name + ".sv.tmp-*")
	if len(matches) > 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestRoundtripSM4(t *testing.T) {
	pass := "sm4-test-pass"
	name := "sm4roundtrip"

	if err := Initialize("SM4", "server", name, pass, "Argon2id"); err != nil {
		t.Fatalf("Initialize SM4: %v", err)
	}

	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault SM4: %v", err)
	}
	if h.Header.AlgId != 0x02 { // AlgIDSM4
		t.Errorf("AlgId = 0x%02x, want 0x02", h.Header.AlgId)
	}

	// Corrupt passphrase must fail.
	if _, err := loadVault(path, "wrong"); err == nil {
		t.Error("expected error with wrong passphrase")
	}
}
