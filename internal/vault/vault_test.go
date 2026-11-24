package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if h.Header.AlgId != alg.AlgIDSM4 {
		t.Errorf("AlgId = 0x%02x, want 0x%02x", h.Header.AlgId, alg.AlgIDSM4)
	}

	// Encrypt + save a real item through EncryptVaultItem / saveVault — this
	// is where chunkKey gets used as EncryptGCM key (must match suite.KeyLen).
	item := VaultItem{
		Label:    "db-password",
		Account:  "admin",
		Password: "s3cr3t-👻-中文",
		Category: "server",
	}
	block, err := EncryptVaultItem(item, h.DataKey, h.MacKey, h.AlgSuite, 1)
	if err != nil {
		t.Fatalf("EncryptVaultItem (SM4): %v", err)
	}
	h.BodyBlocks = append(h.BodyBlocks, block)
	if err := saveVault(h); err != nil {
		t.Fatalf("saveVault with SM4 item: %v", err)
	}

	// Reload and decrypt the item back.
	h2, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload after item save: %v", err)
	}
	if len(h2.BodyBlocks) != 1 {
		t.Fatalf("want 1 block, got %d", len(h2.BodyBlocks))
	}
	got, err := DecryptVaultItem(h2.BodyBlocks[0], h2.MacKey, h2.DataKey, h2.AlgSuite, 1)
	if err != nil {
		t.Fatalf("DecryptVaultItem (SM4): %v", err)
	}
	if got.Password != item.Password {
		t.Errorf("Password roundtrip mismatch: got %q, want %q", got.Password, item.Password)
	}

	// Corrupt passphrase must fail.
	if _, err := loadVault(path, "wrong"); err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestSeqLimit(t *testing.T) {
	pass := "seq-limit-pass"
	name := "seqlimit"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault: %v", err)
	}
	h.Header.NextSeq = MaxSeq
	if err := saveVault(h); err != nil {
		t.Fatalf("saveVault: %v", err)
	}

	// Two new items would need Seq 50000 and 50001 — must be rejected as a whole.
	two := filepath.Join(t.TempDir(), "two.json")
	if err := os.WriteFile(two, []byte(`[{"label":"a","category":"email","password":"p1"},{"label":"b","category":"email","password":"p2"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveVaultItem(path, two, pass); err == nil {
		t.Fatal("expected seq limit error when allocating beyond MaxSeq")
	}

	h2, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if h2.Header.Count != 0 || len(h2.BodyBlocks) != 0 || h2.Header.NextSeq != MaxSeq {
		t.Errorf("vault changed after rejected add: count=%d blocks=%d nextSeq=%d",
			h2.Header.Count, len(h2.BodyBlocks), h2.Header.NextSeq)
	}

	// Exactly one item fits at the cap.
	one := filepath.Join(t.TempDir(), "one.json")
	if err := os.WriteFile(one, []byte(`{"label":"last","category":"email","password":"p3"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveVaultItem(path, one, pass); err != nil {
		t.Fatalf("single item at MaxSeq should succeed: %v", err)
	}
	h3, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(h3.BodyBlocks) != 1 || h3.BodyBlocks[0].Seq != MaxSeq {
		t.Errorf("want one block with seq %d, got %d block(s)", MaxSeq, len(h3.BodyBlocks))
	}
	if h3.Header.NextSeq != MaxSeq+1 {
		t.Errorf("NextSeq = %d, want %d", h3.Header.NextSeq, MaxSeq+1)
	}

	// Cap reached — further adds must fail rather than wrap around.
	if err := SaveVaultItem(path, one, pass); err == nil {
		t.Fatal("expected seq limit error after reaching MaxSeq")
	}
}

func TestLabelIndexInconsistent(t *testing.T) {
	h := &VaultHandle{
		Base:       VaultBase{Labels: []string{"a", "b"}},
		BodyBlocks: []VaultBlock{{Seq: 1}},
	}
	if _, err := labelIndex(h); err == nil {
		t.Fatal("expected error when label count != block count")
	}

	h = &VaultHandle{
		Base:       VaultBase{Labels: []string{"a", "a"}},
		BodyBlocks: []VaultBlock{{Seq: 1}, {Seq: 2}},
	}
	if _, err := labelIndex(h); err == nil {
		t.Fatal("expected error on duplicate label")
	}
}

func TestSelectiveOperations(t *testing.T) {
	pass := "selective-pass"
	name := "selective"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() {
		os.Remove(path)
		for _, l := range []string{"a", "b", "c"} {
			os.Remove("email-" + l + ".json")
		}
	})

	writeTemp := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	initial := `[{"label":"a","category":"email","password":"p1"},
	             {"label":"b","category":"email","password":"p2"},
	             {"label":"c","category":"email","password":"p3"}]`
	if err := SaveVaultItem(path, writeTemp("init.json", initial), pass); err != nil {
		t.Fatalf("SaveVaultItem: %v", err)
	}

	// Update only "b" — must locate it via the label index and leave others intact.
	if err := UpdateVaultItem(path, writeTemp("upd.json", `{"label":"b","category":"email","password":"newb"}`), pass, false); err != nil {
		t.Fatalf("UpdateVaultItem: %v", err)
	}

	passwords := func() map[string]string {
		h, err := loadVault(path, pass)
		if err != nil {
			t.Fatalf("loadVault: %v", err)
		}
		defer h.Clear()
		out := make(map[string]string, len(h.BodyBlocks))
		for _, b := range h.BodyBlocks {
			item, err := DecryptVaultItem(b, h.MacKey, h.DataKey, h.AlgSuite, b.Seq)
			if err != nil {
				t.Fatalf("decrypt seq %d: %v", b.Seq, err)
			}
			out[item.Label] = item.Password
		}
		return out
	}

	got := passwords()
	if got["b"] != "newb" || got["a"] != "p1" || got["c"] != "p3" {
		t.Errorf("unexpected passwords after selective update: %v", got)
	}

	// pop must decrypt only the requested block.
	if err := ExtractVaultItem(path, []string{"c"}, pass); err != nil {
		t.Fatalf("ExtractVaultItem: %v", err)
	}
	data, err := os.ReadFile("email-c.json")
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	var exported VaultItem
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("unmarshal exported file: %v", err)
	}
	if exported.Label != "c" || exported.Password != "p3" {
		t.Errorf("exported item = %+v, want label c / password p3", exported)
	}

	// Delete "a" without decrypting any remaining block.
	if err := DeleteVaultItem(path, []string{"a"}, pass, false); err != nil {
		t.Fatalf("DeleteVaultItem: %v", err)
	}
	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload after delete: %v", err)
	}
	if h.Header.Count != 2 || len(h.BodyBlocks) != 2 {
		t.Errorf("after delete: count=%d blocks=%d, want 2/2", h.Header.Count, len(h.BodyBlocks))
	}
	if strings.Join(h.Base.Labels, ",") != "b,c" {
		t.Errorf("labels = %v, want [b c]", h.Base.Labels)
	}
	h.Clear()

	if err := ExtractVaultItem(path, []string{"a"}, pass); err == nil {
		t.Error("expected 'no matching labels' after deleting a")
	}
}
