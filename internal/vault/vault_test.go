package vault

import (
	"encoding/json"
	"fmt"
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
	h.Base.Labels = append(h.Base.Labels, item.Label)
	h.Header.Count = uint32(len(h.BodyBlocks))
	h.Header.NextSeq = uint32(block.Seq) + 1
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

func TestLargeBaseMetadata(t *testing.T) {
	pass := "baselen-pass"
	name := "baselen"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	// 40 short labels push BaseCipher past the old 255-byte u8 limit; the
	// uint32 BaseLen field must represent and preserve the full length.
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 40; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"label":"label-%02d","category":"email","password":"p"}`, i)
	}
	sb.WriteString("]")

	in := filepath.Join(t.TempDir(), "many.json")
	if err := os.WriteFile(in, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SaveVaultItem(path, in, pass); err != nil {
		t.Fatalf("SaveVaultItem: %v", err)
	}

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer h.Clear()
	if h.Header.Count != 40 || len(h.BodyBlocks) != 40 {
		t.Fatalf("count=%d blocks=%d, want 40/40", h.Header.Count, len(h.BodyBlocks))
	}
	if len(h.Base.Labels) != 40 {
		t.Fatalf("labels=%d, want 40", len(h.Base.Labels))
	}
	if len(h.Header.BaseCipher) <= 255 {
		t.Fatalf("BaseCipher=%d bytes, test requires >255 to exercise the widened field", len(h.Header.BaseCipher))
	}
	if h.Header.BaseLen != uint32(len(h.Header.BaseCipher)) {
		t.Fatalf("BaseLen=%d, want %d", h.Header.BaseLen, len(h.Header.BaseCipher))
	}
}

func TestUnsafeLabelsRejected(t *testing.T) {
	pass := "label-pass"
	name := "labels"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	cases := []struct{ name, json string }{
		{"traversal", `{"label":"../evil","category":"email","password":"p"}`},
		{"slash", `{"label":"a/b","category":"email","password":"p"}`},
		{"backslash", `{"label":"a\\\\b","category":"email","password":"p"}`},
		{"dotdot", `{"label":"..","category":"email","password":"p"}`},
		{"tenant", `{"label":".","category":"email","password":"p"}`},
		{"comma", `{"label":"a,b","category":"email","password":"p"}`},
		{"space", `{"label":"a b","category":"email","password":"p"}`},
		{"tab", `{"label":"a\tb","category":"email","password":"p"}`},
		{"ideographic-space", `{"label":"a\u3000b","category":"email","password":"p"}`},
		{"control", `{"label":"bad\u0001name","category":"email","password":"p"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "bad.json")
			if err := os.WriteFile(in, []byte(c.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := SaveVaultItem(path, in, pass); err == nil {
				t.Fatalf("expected label %s to be rejected", c.name)
			}
		})
	}

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer h.Clear()
	if h.Header.Count != 0 {
		t.Errorf("count = %d, want 0 (no partial writes)", h.Header.Count)
	}
}

func TestExportRefusesUnsafeFileName(t *testing.T) {
	items := []VaultItem{{Label: "../escape", Category: "email"}}
	if err := writeItemsAsLabelFiles(items, "email-", false, false); err == nil {
		t.Fatal("expected unsafe label to be rejected on export")
	}

	// A crafted category prefix must be caught by the file-name check too.
	items = []VaultItem{{Label: "ok", Category: "email"}}
	if err := writeItemsAsLabelFiles(items, "../", false, false); err == nil {
		t.Fatal("expected path in prefix to be rejected on export")
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

func TestCipherLenLimit(t *testing.T) {
	pass := "cipherlen-pass"
	name := "cipherlen"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	// A single item whose encrypted size exceeds the u16 CipherLen field.
	huge := strings.Repeat("x", 70000)
	body := fmt.Sprintf(`{"label":"huge","category":"email","password":"p","notes":["%s"]}`, huge)
	in := filepath.Join(t.TempDir(), "huge.json")
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SaveVaultItem(path, in, pass); err == nil {
		t.Fatal("expected oversized item to be rejected, got nil")
	}

	h, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("vault must stay readable: %v", err)
	}
	defer h.Clear()
	if h.Header.Count != 0 || len(h.BodyBlocks) != 0 {
		t.Errorf("vault changed after rejected add: count=%d blocks=%d", h.Header.Count, len(h.BodyBlocks))
	}
}

func TestPassphraseTooShort(t *testing.T) {
	name := "shortpass"
	err := Initialize("AES", "email", name, "short", "PBKDF2")
	if err == nil {
		t.Fatal("expected short passphrase to be rejected")
	}
	if _, statErr := os.Stat(name + ".sv"); statErr == nil {
		os.Remove(name + ".sv")
		t.Fatal("vault file must not be created when validation fails")
	}
}

func TestDecryptVaultItemSeqMismatch(t *testing.T) {
	suite, err := alg.NewSuite("AES")
	if err != nil {
		t.Fatal(err)
	}
	dataKey := make([]byte, suite.KeyLen())
	macKey := make([]byte, alg.DefaultMacLen)

	item := VaultItem{Label: "x", Category: "email", Password: "p"}
	block, err := EncryptVaultItem(item, dataKey, macKey, suite, 7)
	if err != nil {
		t.Fatalf("EncryptVaultItem: %v", err)
	}

	if _, err := DecryptVaultItem(block, macKey, dataKey, suite, 8); err == nil {
		t.Fatal("expected sequence mismatch error")
	}
	if _, err := DecryptVaultItem(block, macKey, dataKey, suite, 7); err != nil {
		t.Fatalf("decrypt with correct seq: %v", err)
	}
}

func TestHeaderCountMismatchRejected(t *testing.T) {
	pass := "count-mismatch-pass"
	name := "countmismatch"
	if err := Initialize("AES", "email", name, pass, "PBKDF2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	path := name + ".sv"
	t.Cleanup(func() { os.Remove(path) })

	in := filepath.Join(t.TempDir(), "one.json")
	if err := os.WriteFile(in, []byte(`{"label":"one","category":"email","password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveVaultItem(path, in, pass); err != nil {
		t.Fatalf("SaveVaultItem: %v", err)
	}

	// Tamper with Count and re-sign the file with the correct macKey, so the
	// only remaining inconsistency is Count vs. block count.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr, blocks, err := DeserializeVault(data)
	if err != nil {
		t.Fatalf("DeserializeVault: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(blocks))
	}
	hdr.Count = uint32(len(blocks)) + 1
	hdr.MacLen, hdr.Mac = 0, nil
	headerBytes, err := SerializeHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}

	root, err := alg.DeriveRootKey(pass, alg.KDFParams{
		ID: hdr.KdfId, M: hdr.KdfParamM, T: hdr.KdfParamT, P: hdr.KdfParamP, Salt: hdr.Salt,
	})
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := alg.DeriveMacKey(root)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ComputeVaultMAC(macKey, headerBytes, blocks)
	if err != nil {
		t.Fatal(err)
	}
	hdr.Mac, hdr.MacLen = mac, byte(len(mac))

	out, err := SerializeVault(hdr, blocks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadVault(path, pass); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("expected count mismatch error, got %v", err)
	}
}
