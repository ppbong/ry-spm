package vault

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ppbong/ry-spm/internal/alg"
	"github.com/ppbong/ry-spm/internal/util"
)

const (
	MaxRecordCount = 10000
	// MaxSeq caps the block sequence number below the uint16 limit (65535)
	// so that a wrapped NextSeq can never reuse an existing Seq.
	MaxSeq = 50000
)

// loadVault reads a vault file, verifies structure and MAC, and prepares the handle.
// passphrase is tried as master first, then secondary.
func loadVault(vaultFile string, passphrase string) (*VaultHandle, error) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file %s: %w", vaultFile, err)
	}

	header, blocks, err := DeserializeVault(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault file: %w", err)
	}

	suite, err := alg.NewSuiteByID(header.AlgId)
	if err != nil {
		return nil, err
	}

	kdfParams := alg.KDFParams{
		Name: "",
		ID:   header.KdfId,
		M:    header.KdfParamM,
		T:    header.KdfParamT,
		P:    header.KdfParamP,
		Salt: header.Salt,
	}

	masterRootKey, err := alg.DeriveRootKey(passphrase, kdfParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive root key: %w", err)
	}
	masterDataKey, err := alg.DeriveSubKey(masterRootKey, "data-key", uint32(suite.KeyLen()))
	if err != nil {
		return nil, err
	}
	masterMacKey, err := alg.DeriveMacKey(masterRootKey)
	if err != nil {
		return nil, err
	}

	// Compute vault MAC using master MacKey — headerBytes must NOT contain MAC
	headerForMAC := header
	headerForMAC.MacLen = 0
	headerForMAC.Mac = nil
	headerBytes, _ := SerializeHeader(headerForMAC)
	expectedMAC, err := ComputeVaultMAC(masterMacKey, headerBytes, blocks)
	if err == nil && hmac.Equal(expectedMAC, header.Mac) {
		handle := &VaultHandle{
			FilePath:   vaultFile,
			AlgSuite:   suite,
			KdfParams:  kdfParams,
			RootKey:    masterRootKey,
			DataKey:    masterDataKey,
			MacKey:     masterMacKey,
			Header:     header,
			BodyBlocks: blocks,
		}
		// Decrypt Base using infoKey derived from rootKey.
		infoKey, _ := alg.DeriveSubKey(masterRootKey, "info-key", uint32(suite.KeyLen()))
		handle.InfoKey = infoKey
		if base, err := DecryptVaultBase(header.BaseCipher, infoKey, suite); err == nil {
			handle.Base = base
			handle.BaseDecrypted = true
		}
		return handle, nil
	}

	return nil, fmt.Errorf("passphrase is incorrect or vault is corrupted")
}

// LoadVaultLite reads a vault file, verifies structure + MAC, and prepares
// the handle with only Header + Base metadata populated — BodyBlocks are nil.
// Use this for commands that only need vault-level info (e.g. `spm info`)
// where full item deserialization is wasted.
func LoadVaultLite(vaultFile, passphrase string) (*VaultHandle, error) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file %s: %w", vaultFile, err)
	}

	header, bodyBytes, err := DeserializeVaultHeaderOnly(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault file: %w", err)
	}

	suite, err := alg.NewSuiteByID(header.AlgId)
	if err != nil {
		return nil, err
	}

	kdfParams := alg.KDFParams{
		Name: "",
		ID:   header.KdfId,
		M:    header.KdfParamM,
		T:    header.KdfParamT,
		P:    header.KdfParamP,
		Salt: header.Salt,
	}

	masterRootKey, err := alg.DeriveRootKey(passphrase, kdfParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive root key: %w", err)
	}
	masterMacKey, err := alg.DeriveMacKey(masterRootKey)
	if err != nil {
		return nil, err
	}

	headerForMAC := header
	headerForMAC.MacLen = 0
	headerForMAC.Mac = nil
	headerBytes, _ := SerializeHeader(headerForMAC)
	expectedMAC := ComputeVaultMACRaw(masterMacKey, headerBytes, bodyBytes)
	if hmac.Equal(expectedMAC, header.Mac) {
		infoKey, _ := alg.DeriveSubKey(masterRootKey, "info-key", uint32(suite.KeyLen()))
		handle := &VaultHandle{
			FilePath:  vaultFile,
			AlgSuite:  suite,
			KdfParams: kdfParams,
			RootKey:   masterRootKey,
			MacKey:    masterMacKey,
			InfoKey:   infoKey,
			Header:    header,
			// DataKey intentionally nil — Lite mode never decrypts items.
		}
		if base, err := DecryptVaultBase(header.BaseCipher, infoKey, suite); err == nil {
			handle.Base = base
			handle.BaseDecrypted = true
		}
		return handle, nil
	}
	return nil, fmt.Errorf("passphrase is incorrect or vault is corrupted")
}

// saveVault writes the vault back to disk, recomputing MAC and timestamps.
func saveVault(h *VaultHandle) error {
	// Re-encrypt Base
	if h.BaseDecrypted && h.InfoKey != nil {
		cipher, err := EncryptVaultBase(h.Base, h.InfoKey, h.AlgSuite)
		if err != nil {
			return err
		}
		h.Header.BaseCipher = cipher
		h.Header.BaseLen = byte(len(cipher))
	}

	// Update timestamps
	now := util.NowString()
	h.Header.LastUsedAt = now
	if h.Header.UpdatedAt == "" {
		h.Header.UpdatedAt = now
	}

	// Recompute vault MAC — headerBytes must NOT contain MAC
	h.Header.MacLen = 0
	h.Header.Mac = nil
	headerBytes, err := SerializeHeader(h.Header)
	if err != nil {
		return err
	}
	mac, err := ComputeVaultMAC(h.MacKey, headerBytes, h.BodyBlocks)
	if err != nil {
		return err
	}
	h.Header.Mac = mac
	h.Header.MacLen = byte(len(mac))

	data, err := SerializeVault(h.Header, h.BodyBlocks)
	if err != nil {
		return err
	}

	if err := util.WriteFileAtomic(h.FilePath, data); err != nil {
		return err
	}
	return nil
}

// Initialize creates a new .sv vault file in the current directory.
// passphrase are required.
func Initialize(algName, category, vaultName, passphrase, kdfName string) error {
	if !util.ValidatePassphrase(passphrase, 64) {
		return fmt.Errorf("master passphrase cannot be empty and be <= 64 chars")
	}

	if !util.ValidateIdentifier(category, 32) {
		return fmt.Errorf("invalid category: must match [A-Za-z0-9_-] and be <= 32 chars")
	}
	if vaultName == "" {
		vaultName = category
	}
	if !util.ValidateIdentifier(vaultName, 64) {
		return fmt.Errorf("invalid vault name: must match [A-Za-z0-9_-] and be <= 64 chars")
	}

	suite, err := alg.NewSuite(algName)
	if err != nil {
		return err
	}
	kdfParams, err := alg.NewKDFParams(kdfName)
	if err != nil {
		return err
	}

	rootKey, err := alg.DeriveRootKey(passphrase, kdfParams)
	if err != nil {
		return fmt.Errorf("failed to derive root key: %w", err)
	}
	macKey, err := alg.DeriveMacKey(rootKey)
	if err != nil {
		return err
	}
	infoKey, err := alg.DeriveSubKey(rootKey, "info-key", uint32(suite.KeyLen()))
	if err != nil {
		return err
	}

	base := VaultBase{
		Tag:      "RY",
		AlgName:  suite.Name(),
		KdfName:  kdfParams.Name,
		Category: category,
		Labels:   []string{},
	}

	cipher, err := EncryptVaultBase(base, infoKey, suite)
	if err != nil {
		return err
	}

	now := util.NowString()
	header := VaultHeader{
		BaseLen:    byte(len(cipher)),
		BaseCipher: cipher,
		AlgId:      suite.ID(),
		KdfId:      kdfParams.ID,
		KdfParamM:  kdfParams.M,
		KdfParamT:  kdfParams.T,
		KdfParamP:  kdfParams.P,
		SaltLen:    byte(len(kdfParams.Salt)),
		Salt:       kdfParams.Salt,
		Count:      0,
		NextSeq:    1,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastUsedAt: now,
	}

	// Compute vault MAC
	headerBytes, err := SerializeHeader(header)
	if err != nil {
		return err
	}
	body := []VaultBlock{}
	mac, err := ComputeVaultMAC(macKey, headerBytes, body)
	if err != nil {
		return err
	}
	header.Mac = mac
	header.MacLen = byte(len(mac))

	data, err := SerializeVault(header, body)
	if err != nil {
		return err
	}

	vaultPath := util.VaultPath(vaultName)
	if util.FileExists(vaultPath) {
		return fmt.Errorf("vault file %s already exists", vaultPath)
	}

	if err := util.WriteFileAtomic(vaultPath, data); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	fmt.Printf("Vault created successfully: %s\n", vaultPath)
	fmt.Printf("  Algorithm : %s\n", suite.Name())
	fmt.Printf("  KDF       : %s\n", kdfParams.Name)
	fmt.Printf("  Category  : %s\n", category)
	fmt.Printf("  CreatedAt : %s\n", now)
	return nil
}

// MockVaultItem generates a template JSON file.
func MockVaultItem(vaultFile, filename, passphrase string) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	if !handle.BaseDecrypted {
		return fmt.Errorf("cannot access vault info with this passphrase")
	}

	mock := MockVaultItemJSON(handle.Base.Category)

	outName := filename
	if outName == "" {
		outName = "mock-" + handle.Base.Category
	}
	outPath := util.JSONPath(outName)

	data, err := json.MarshalIndent(mock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal mock template: %w", err)
	}
	if err := util.WriteFile(outPath, data); err != nil {
		return err
	}
	fmt.Printf("Mock template generated: %s\n", outPath)
	return nil
}

// SaveVaultItem reads a JSON file and adds all entries into the vault.
func SaveVaultItem(vaultFile, filename, passphrase string) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	jsonData, err := util.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var items []MockItem
	single := MockItem{}
	if err := json.Unmarshal(jsonData, &items); err != nil {
		if err2 := json.Unmarshal(jsonData, &single); err2 != nil {
			return fmt.Errorf("input file is not valid JSON array or object: %w", err)
		}
		items = []MockItem{single}
	}

	if len(items)+int(handle.Header.Count) > MaxRecordCount {
		return fmt.Errorf("input file contains %d items, which exceeds the maximum record count of %d", len(items), MaxRecordCount)
	}
	if len(items) > 0 {
		lastSeq := uint64(handle.Header.NextSeq) + uint64(len(items)) - 1
		if lastSeq > MaxSeq {
			return fmt.Errorf("sequence number limit exceeded: requested %d item(s) starting at seq %d, but max seq is %d",
				len(items), handle.Header.NextSeq, MaxSeq)
		}
	}

	for _, m := range items {
		if m.Category != handle.Base.Category {
			return fmt.Errorf("each item must belong to the vault category %s", handle.Base.Category)
		}
		if strings.TrimSpace(m.Label) == "" {
			return fmt.Errorf("each item must have a non-empty label")
		}
	}

	for _, m := range items {
		item := ToVaultItem(m, handle.Base.Category)

		// Check duplicate label
		for _, existing := range handle.Base.Labels {
			if existing == item.Label {
				return fmt.Errorf("label %q already exists in vault", item.Label)
			}
		}

		seq := uint16(handle.Header.NextSeq)
		block, err := EncryptVaultItem(item, handle.DataKey, handle.MacKey, handle.AlgSuite, seq)
		if err != nil {
			return err
		}
		handle.BodyBlocks = append(handle.BodyBlocks, block)
		handle.Base.Labels = append(handle.Base.Labels, item.Label)
		handle.Header.Count++
		handle.Header.NextSeq++
	}

	handle.Header.UpdatedAt = util.NowString()
	if err := saveVault(handle); err != nil {
		return err
	}
	fmt.Printf("Added %d item(s) to vault.\n", len(items))
	return nil
}

// DeleteVaultItem removes records by label, optionally exporting them first.
func DeleteVaultItem(vaultFile string, labels []string, passphrase string, pop bool) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	if _, err := labelIndex(handle); err != nil {
		return err
	}

	labelSet := make(map[string]bool, len(labels))
	for _, l := range labels {
		labelSet[l] = true
	}

	var remainingBlocks []VaultBlock
	var remainingLabels []string
	var removedBlocks []VaultBlock

	for i, l := range handle.Base.Labels {
		if labelSet[l] {
			removedBlocks = append(removedBlocks, handle.BodyBlocks[i])
			continue
		}
		remainingLabels = append(remainingLabels, l)
		remainingBlocks = append(remainingBlocks, handle.BodyBlocks[i])
	}

	// Decrypt only the blocks being exported, before mutating the vault, so a
	// corrupted block aborts the whole operation instead of leaving it deleted.
	var removedItems []VaultItem
	if pop {
		for _, b := range removedBlocks {
			item, err := DecryptVaultItem(b, handle.MacKey, handle.DataKey, handle.AlgSuite, b.Seq)
			if err != nil {
				return fmt.Errorf("failed to decrypt deleted block seq %d: %w", b.Seq, err)
			}
			if !labelSet[item.Label] {
				return fmt.Errorf("vault is inconsistent: block seq %d holds unexpected label %q", b.Seq, item.Label)
			}
			removedItems = append(removedItems, item)
		}
	}

	handle.BodyBlocks = remainingBlocks
	handle.Base.Labels = remainingLabels
	handle.Header.Count = uint32(len(remainingBlocks))
	handle.Header.UpdatedAt = util.NowString()

	if err := saveVault(handle); err != nil {
		return err
	}

	fmt.Printf("Deleted %d item(s) from vault.\n", len(removedBlocks))

	if pop && len(removedItems) > 0 {
		return writeItemsAsLabelFiles(removedItems, handle.Base.Category+"-", true, false)
	}
	return nil
}

// ExtractVaultItem exports records by label as JSON files without deletion.
func ExtractVaultItem(vaultFile string, labels []string, passphrase string) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	if _, err := labelIndex(handle); err != nil {
		return err
	}

	labelSet := make(map[string]bool, len(labels))
	for _, l := range labels {
		labelSet[l] = true
	}

	var matched []VaultItem
	for i, l := range handle.Base.Labels {
		if !labelSet[l] {
			continue
		}
		item, err := decryptBlockAt(handle, i, l)
		if err != nil {
			return err
		}
		matched = append(matched, item)
	}

	if len(matched) == 0 {
		return fmt.Errorf("no matching labels found")
	}

	return writeItemsAsLabelFiles(matched, handle.Base.Category+"-", false, false)
}

// ShowVaultInfo prints vault information.
func ShowVaultInfo(vaultFile, passphrase string) error {
	handle, err := LoadVaultLite(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	fmt.Println("=== Vault Info ===")
	fmt.Printf("File       : %s\n", handle.FilePath)
	fmt.Printf("Algorithm  : 0x%02X (%s)\n", handle.Header.AlgId, alg.AlgNameByID(handle.Header.AlgId))
	fmt.Printf("KDF        : 0x%02X (%s)\n", handle.Header.KdfId, alg.KdfNameByID(handle.Header.KdfId))
	fmt.Printf("Count      : %d\n", handle.Header.Count)
	fmt.Printf("NextSeq    : %d\n", handle.Header.NextSeq)
	fmt.Printf("CreatedAt  : %s\n", handle.Header.CreatedAt)
	fmt.Printf("UpdatedAt  : %s\n", handle.Header.UpdatedAt)
	fmt.Printf("LastUsedAt : %s\n", handle.Header.LastUsedAt)

	if handle.BaseDecrypted {
		fmt.Println("--- Decrypted Info ---")
		fmt.Printf("Tag        : %s\n", handle.Base.Tag)
		fmt.Printf("Category   : %s\n", handle.Base.Category)
		fmt.Printf("AlgName    : %s\n", handle.Base.AlgName)
		fmt.Printf("KdfName    : %s\n", handle.Base.KdfName)
		fmt.Printf("Labels     : %v\n", handle.Base.Labels)
	} else {
		fmt.Println("--- (sensitive info requires master passphrase) ---")
	}

	if handle.Header.LastUsedAt != "" {
		if t, err := util.ParseAnyFormat(handle.Header.LastUsedAt); err == nil {
			if util.IsOverdueForBackup(t) {
				fmt.Println("\n[!] Vault has not been used for over 90 days. Consider backing up.")
			}
		}
	}
	return nil
}

// ShowVaultItemDetail prints full details of records including plaintext passwords.
func ShowVaultItemDetail(vaultFile string, labels []string, passphrase string) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	if _, err := labelIndex(handle); err != nil {
		return err
	}

	labelSet := make(map[string]bool, len(labels))
	for _, l := range labels {
		labelSet[l] = true
	}

	foundAny := false
	for i, l := range handle.Base.Labels {
		if len(labelSet) > 0 && !labelSet[l] {
			continue
		}
		item, err := decryptBlockAt(handle, i, l)
		if err != nil {
			return err
		}
		foundAny = true
		fmt.Println("------------------------------")
		fmt.Printf("Label           : %s\n", item.Label)
		fmt.Printf("Category        : %s\n", item.Category)
		fmt.Printf("Account         : %s\n", item.Account)
		fmt.Printf("Password        : %s\n", item.Password)
		fmt.Printf("BindEmail       : %s\n", item.BindEmail)
		fmt.Printf("BindPhone       : %s\n", item.BindPhone)
		fmt.Printf("URLs            : %v\n", item.Urls)
		fmt.Printf("Notes           : %v\n", item.Notes)
		fmt.Printf("RegisteredAt    : %s\n", item.RegisteredAt)
		fmt.Printf("CreatedAt       : %s\n", item.CreatedAt)
		fmt.Printf("UpdatedAt       : %s\n", item.UpdatedAt)
		if len(item.HistoryPasswords) > 0 {
			fmt.Printf("HistoryPasswords: %v\n", item.HistoryPasswords)
		}
		// Drop the plaintext reference as soon as it has been printed so only
		// one item is live at a time.
		item = VaultItem{}
	}

	if !foundAny {
		return fmt.Errorf("no matching labels found")
	}
	return nil
}

// UpdateVaultItem updates records in the vault from a JSON file.
func UpdateVaultItem(vaultFile, filename, passphrase string, keepHistory bool) error {
	handle, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer handle.Clear()

	jsonData, err := util.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var updates []MockItem
	single := MockItem{}
	if err := json.Unmarshal(jsonData, &updates); err != nil {
		if err2 := json.Unmarshal(jsonData, &single); err2 != nil {
			return fmt.Errorf("input file is not valid JSON array or object: %w", err)
		}
		updates = []MockItem{single}
	}

	idx, err := labelIndex(handle)
	if err != nil {
		return err
	}

	updateMap := make(map[string]MockItem)
	for _, u := range updates {
		if u.Category != handle.Base.Category {
			return fmt.Errorf("each update must belong to the vault category %s", handle.Base.Category)
		}
		if strings.TrimSpace(u.Label) == "" {
			return fmt.Errorf("each update must have a non-empty label")
		}
		updateMap[u.Label] = u
	}

	var missing []string
	for l := range updateMap {
		if _, ok := idx[l]; !ok {
			missing = append(missing, l)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("labels not found in vault for update: %v", missing)
	}

	newBlocks := make([]VaultBlock, 0, len(handle.BodyBlocks))
	for i, l := range handle.Base.Labels {
		u, wantUpdate := updateMap[l]
		if !wantUpdate {
			newBlocks = append(newBlocks, handle.BodyBlocks[i])
			continue
		}

		item, err := decryptBlockAt(handle, i, l)
		if err != nil {
			return err
		}

		oldPassword := item.Password
		newItem := item
		newItem.Account = strings.TrimSpace(u.Account)
		newItem.Password = u.Password
		newItem.BindEmail = strings.TrimSpace(u.BindEmail)
		newItem.BindPhone = strings.TrimSpace(u.BindPhone)
		newItem.Urls = u.Urls
		newItem.Notes = u.Notes
		newItem.RegisteredAt = strings.TrimSpace(u.RegisteredAt)
		newItem.UpdatedAt = util.NowString()

		if keepHistory && oldPassword != "" && oldPassword != newItem.Password {
			found := false
			for _, hp := range newItem.HistoryPasswords {
				if hp == oldPassword {
					found = true
					break
				}
			}
			if !found {
				newItem.HistoryPasswords = append(newItem.HistoryPasswords, oldPassword)
			}
		}

		newBlock, err := EncryptVaultItem(newItem, handle.DataKey, handle.MacKey, handle.AlgSuite, handle.BodyBlocks[i].Seq)
		if err != nil {
			return err
		}
		newBlocks = append(newBlocks, newBlock)
		delete(updateMap, l)
	}

	handle.BodyBlocks = newBlocks
	handle.Header.UpdatedAt = util.NowString()

	if err := saveVault(handle); err != nil {
		return err
	}
	fmt.Printf("Updated %d item(s) in vault.\n", len(updates))
	return nil
}

// labelIndex validates the "Base.Labels[i] corresponds to BodyBlocks[i]"
// invariant and returns a label-to-index map. Selective operations rely on
// this invariant to locate a block without decrypting every record.
func labelIndex(h *VaultHandle) (map[string]int, error) {
	if len(h.Base.Labels) != len(h.BodyBlocks) {
		return nil, fmt.Errorf("vault is inconsistent: %d labels but %d blocks", len(h.Base.Labels), len(h.BodyBlocks))
	}
	idx := make(map[string]int, len(h.Base.Labels))
	for i, l := range h.Base.Labels {
		if _, dup := idx[l]; dup {
			return nil, fmt.Errorf("vault is inconsistent: duplicate label %q", l)
		}
		idx[l] = i
	}
	return idx, nil
}

// decryptBlockAt decrypts BodyBlocks[i] and verifies that it really holds the
// expected label, so a broken index can never cause an update/delete of the
// wrong record.
func decryptBlockAt(h *VaultHandle, i int, wantLabel string) (VaultItem, error) {
	if i < 0 || i >= len(h.BodyBlocks) {
		return VaultItem{}, fmt.Errorf("block index %d out of range", i)
	}
	b := h.BodyBlocks[i]
	item, err := DecryptVaultItem(b, h.MacKey, h.DataKey, h.AlgSuite, b.Seq)
	if err != nil {
		return VaultItem{}, fmt.Errorf("failed to decrypt block seq %d: %w", b.Seq, err)
	}
	if item.Label != wantLabel {
		return VaultItem{}, fmt.Errorf("vault is inconsistent: block %d (seq %d) holds label %q, expected %q",
			i, b.Seq, item.Label, wantLabel)
	}
	return item, nil
}

// writeItemsAsLabelFiles writes each item to a <label>.json file.
func writeItemsAsLabelFiles(items []VaultItem, prefix string, verbose bool, isMock bool) error {
	for _, item := range items {
		var out any
		if isMock {
			out = FromVaultItemToMock(item)
		} else {
			out = item
		}

		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		name := util.JSONPath(prefix + item.Label)
		if err := util.WriteFile(name, data); err != nil {
			return err
		}
		if verbose {
			fmt.Printf("Exported  : %s\n", name)
		}
	}
	return nil
}

// touchLastUsed updates the vault's last-used timestamp without changing other data.
func TouchLastUsed(vaultFile, passphrase string) error {
	h, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return err
	}
	defer h.Clear()
	h.Header.LastUsedAt = util.NowString()
	return saveVault(h)
}

// checkBackupDue returns true if the vault has not been used for over 90 days.
func CheckBackupDue(vaultFile, passphrase string) (bool, error) {
	h, err := loadVault(vaultFile, passphrase)
	if err != nil {
		return false, err
	}
	defer h.Clear()
	if h.Header.LastUsedAt == "" {
		return false, nil
	}
	t, err := util.ParseAnyFormat(h.Header.LastUsedAt)
	if err != nil {
		return false, err
	}
	return util.IsOverdueForBackup(t), nil
}
