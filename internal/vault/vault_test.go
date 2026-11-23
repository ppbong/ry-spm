package vault

import (
	"os"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	pass := "master1234"

	err := Initialize("AES", "email", "testroundtrip", pass, "PBKDF2")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	path := "testroundtrip.sv"
	defer os.Remove(path)

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault master: %v", err)
	}

	t.Logf("PASS: loadVault with master passphrase")

	h.Header.LastUsedAt = "2025-01-01 00:00:00"
	h.Header.UpdatedAt = "2025-01-01 00:00:00"
	err = saveVault(h)
	if err != nil {
		t.Fatalf("saveVault: %v", err)
	}
	t.Log("PASS: saveVault")

	h2, err := loadVault(path, "")
	if err != nil {
		t.Fatalf("loadVault after save: %v", err)
	}

	t.Logf("last used at %s updated at %s", h2.Header.LastUsedAt, h2.Header.UpdatedAt)
	t.Log("PASS: loadVault without master passphrase")

	os.Remove(path)
	t.Log("=== ALL ROUND-TRIP TESTS PASSED ===")
}
