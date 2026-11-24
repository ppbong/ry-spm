package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ppbong/ry-spm/internal/alg"
	"github.com/ppbong/ry-spm/internal/util"
)

const (
	Magic   = "RYSPMSVF"
	Version = "1.0"
	Trailer = "YR"
)

// encodeString writes a length-prefixed UTF-8 string to buf.
func encodeString(buf *[]byte, s string) {
	b := []byte(s)
	*buf = append(*buf, util.Uint16ToBytes(uint16(len(b)))...)
	*buf = append(*buf, b...)
}

// decodeString reads a length-prefixed UTF-8 string from data starting at offset.
func decodeString(data []byte, offset int) (string, int, error) {
	if offset+2 > len(data) {
		return "", 0, fmt.Errorf("not enough bytes for string length")
	}
	strLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+strLen > len(data) {
		return "", 0, fmt.Errorf("not enough bytes for string content")
	}
	return string(data[offset : offset+strLen]), offset + strLen, nil
}

// SerializeHeader converts VaultHeader to bytes.
func SerializeHeader(h VaultHeader) ([]byte, error) {
	var buf []byte
	buf = append(buf, h.BaseLen)
	buf = append(buf, h.BaseCipher...)
	buf = append(buf, h.AlgId)
	buf = append(buf, h.KdfId)
	buf = append(buf, util.Uint32ToBytes(h.KdfParamM)...)
	buf = append(buf, h.KdfParamT)
	buf = append(buf, h.KdfParamP)
	buf = append(buf, h.SaltLen)
	buf = append(buf, h.Salt...)
	buf = append(buf, h.MacLen)
	buf = append(buf, h.Mac...)
	buf = append(buf, util.Uint32ToBytes(h.Count)...)
	buf = append(buf, util.Uint32ToBytes(h.NextSeq)...)

	encodeString(&buf, h.CreatedAt)
	encodeString(&buf, h.UpdatedAt)
	encodeString(&buf, h.LastUsedAt)

	return buf, nil
}

// DeserializeHeader parses bytes into VaultHeader.
func DeserializeHeader(data []byte) (VaultHeader, error) {
	h := VaultHeader{}
	offset := 0

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read BaseLen")
	}
	h.BaseLen = data[offset]
	offset++

	if offset+int(h.BaseLen) > len(data) {
		return h, fmt.Errorf("cannot read BaseCipher")
	}
	h.BaseCipher = append([]byte{}, data[offset:offset+int(h.BaseLen)]...)
	offset += int(h.BaseLen)

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read AlgId")
	}
	h.AlgId = data[offset]
	offset++

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read KdfId")
	}
	h.KdfId = data[offset]
	offset++

	if offset+4 > len(data) {
		return h, fmt.Errorf("cannot read KdfParamM")
	}
	h.KdfParamM = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read KdfParamT")
	}
	h.KdfParamT = data[offset]
	offset++

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read KdfParamP")
	}
	h.KdfParamP = data[offset]
	offset++

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read SaltLen")
	}
	h.SaltLen = data[offset]
	offset++

	if offset+int(h.SaltLen) > len(data) {
		return h, fmt.Errorf("cannot read Salt")
	}
	h.Salt = append([]byte{}, data[offset:offset+int(h.SaltLen)]...)
	offset += int(h.SaltLen)

	if offset+1 > len(data) {
		return h, fmt.Errorf("cannot read MacLen")
	}
	h.MacLen = data[offset]
	offset++

	if offset+int(h.MacLen) > len(data) {
		return h, fmt.Errorf("cannot read Mac")
	}
	h.Mac = append([]byte{}, data[offset:offset+int(h.MacLen)]...)
	offset += int(h.MacLen)

	if offset+4 > len(data) {
		return h, fmt.Errorf("cannot read Count")
	}
	h.Count = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+4 > len(data) {
		return h, fmt.Errorf("cannot read NextSeq")
	}
	h.NextSeq = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	var err error
	h.CreatedAt, offset, err = decodeString(data, offset)
	if err != nil {
		return h, fmt.Errorf("cannot read CreatedAt: %w", err)
	}
	h.UpdatedAt, offset, err = decodeString(data, offset)
	if err != nil {
		return h, fmt.Errorf("cannot read UpdatedAt: %w", err)
	}
	h.LastUsedAt, offset, err = decodeString(data, offset)
	if err != nil {
		return h, fmt.Errorf("cannot read LastUsedAt: %w", err)
	}

	return h, nil
}

// SerializeBlock converts VaultBlock to bytes.
func SerializeBlock(b VaultBlock) ([]byte, error) {
	var buf []byte
	buf = append(buf, util.Uint16ToBytes(b.Seq)...)
	buf = append(buf, b.WrappedDekLen)
	buf = append(buf, b.WrappedDek...)
	buf = append(buf, util.Uint16ToBytes(b.CipherLen)...)
	buf = append(buf, b.VaultItemCipher...)
	buf = append(buf, b.MacLen)
	buf = append(buf, b.Mac...)
	return buf, nil
}

// DeserializeBlock reads a single VaultBlock from data starting at offset.
func DeserializeBlock(data []byte, offset int) (VaultBlock, int, error) {
	b := VaultBlock{}

	if offset+2 > len(data) {
		return b, offset, fmt.Errorf("cannot read Seq")
	}
	b.Seq = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+1 > len(data) {
		return b, offset, fmt.Errorf("cannot read WrappedDekLen")
	}
	b.WrappedDekLen = data[offset]
	offset++

	if offset+int(b.WrappedDekLen) > len(data) {
		return b, offset, fmt.Errorf("cannot read WrappedDek")
	}
	b.WrappedDek = append([]byte{}, data[offset:offset+int(b.WrappedDekLen)]...)
	offset += int(b.WrappedDekLen)

	if offset+2 > len(data) {
		return b, offset, fmt.Errorf("cannot read CipherLen")
	}
	b.CipherLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(b.CipherLen) > len(data) {
		return b, offset, fmt.Errorf("cannot read VaultItemCipher")
	}
	b.VaultItemCipher = append([]byte{}, data[offset:offset+int(b.CipherLen)]...)
	offset += int(b.CipherLen)

	if offset+1 > len(data) {
		return b, offset, fmt.Errorf("cannot read MacLen")
	}
	b.MacLen = data[offset]
	offset++

	if offset+int(b.MacLen) > len(data) {
		return b, offset, fmt.Errorf("cannot read Mac")
	}
	b.Mac = append([]byte{}, data[offset:offset+int(b.MacLen)]...)
	offset += int(b.MacLen)

	return b, offset, nil
}

// ComputeVaultMAC computes HMAC-SHA256 over the entire file content (without MAC field itself).
func ComputeVaultMAC(macKey []byte, headerBytes []byte, blocks []VaultBlock) ([]byte, error) {
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(Magic))
	mac.Write([]byte(Version))
	mac.Write(headerBytes)
	for _, b := range blocks {
		blockBytes, err := SerializeBlock(b)
		if err != nil {
			return nil, err
		}
		mac.Write(blockBytes)
	}
	mac.Write([]byte(Trailer))
	return mac.Sum(nil), nil
}

// ComputeVaultMACRaw computes the vault MAC directly from raw body bytes,
// avoiding block-by-block deserialization. Used by LoadVaultLite when only
// header + base are needed.
func ComputeVaultMACRaw(macKey, headerBytes, bodyBytes []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(Magic))
	mac.Write([]byte(Version))
	mac.Write(headerBytes)
	mac.Write(bodyBytes)
	mac.Write([]byte(Trailer))
	return mac.Sum(nil)
}

// SerializeVault serializes the entire vault file to bytes.
func SerializeVault(h VaultHeader, blocks []VaultBlock) ([]byte, error) {
	headerBytes, err := SerializeHeader(h)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	var buf []byte
	buf = append(buf, []byte(Magic)...)
	buf = append(buf, []byte(Version)...)
	buf = append(buf, headerBytes...)
	for _, b := range blocks {
		blockBytes, err := SerializeBlock(b)
		if err != nil {
			return nil, err
		}
		buf = append(buf, blockBytes...)
	}
	buf = append(buf, []byte(Trailer)...)
	return buf, nil
}

// DeserializeVault parses the entire vault file from bytes.
func DeserializeVault(data []byte) (VaultHeader, []VaultBlock, error) {
	header, _, blocks, err := deserializeVaultInner(data, true)
	return header, blocks, err
}

// DeserializeVaultHeaderOnly parses magic/version/header from the file,
// returning the raw body byte slice instead of parsed blocks. This is
// used by LoadVaultLite when only header + base metadata are needed.
func DeserializeVaultHeaderOnly(data []byte) (VaultHeader, []byte, error) {
	header, bodyBytes, _, err := deserializeVaultInner(data, false)
	return header, bodyBytes, err
}

func deserializeVaultInner(data []byte, parseBlocks bool) (VaultHeader, []byte, []VaultBlock, error) {
	minLen := len(Magic) + len(Version) + len(Trailer)
	if len(data) < minLen {
		return VaultHeader{}, nil, nil, fmt.Errorf("file too short")
	}

	if string(data[:len(Magic)]) != Magic {
		return VaultHeader{}, nil, nil, fmt.Errorf("invalid magic header: expected %q, got %q", Magic, string(data[:len(Magic)]))
	}
	version := string(data[len(Magic) : len(Magic)+len(Version)])
	if version != Version {
		return VaultHeader{}, nil, nil, fmt.Errorf("unsupported version: %s", version)
	}
	if string(data[len(data)-len(Trailer):]) != Trailer {
		return VaultHeader{}, nil, nil, fmt.Errorf("invalid trailer")
	}

	headerOffset := len(Magic) + len(Version)
	trailerOffset := len(data) - len(Trailer)

	header, err := DeserializeHeader(data[headerOffset:trailerOffset])
	if err != nil {
		return VaultHeader{}, nil, nil, fmt.Errorf("failed to deserialize header: %w", err)
	}

	headerBytes, err := SerializeHeader(header)
	if err != nil {
		return VaultHeader{}, nil, nil, fmt.Errorf("failed to re-serialize header: %w", err)
	}
	bodyOffset := headerOffset + len(headerBytes)
	bodyBytes := data[bodyOffset:trailerOffset]

	var blocks []VaultBlock
	if parseBlocks {
		var offset int
		var block VaultBlock
		for offset < len(bodyBytes) {
			block, offset, err = DeserializeBlock(bodyBytes, offset)
			if err != nil {
				return VaultHeader{}, nil, nil, fmt.Errorf("failed to deserialize block: %w", err)
			}
			blocks = append(blocks, block)
		}
	}

	return header, bodyBytes, blocks, nil
}

// EncryptVaultBase encrypts VaultBase using the given info key and suite.
func EncryptVaultBase(base VaultBase, infoKey []byte, suite alg.Suite) (ciphertext []byte, err error) {
	plaintext, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VaultBase: %w", err)
	}
	nonce, err := suite.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	encrypted, err := suite.EncryptGCM(infoKey, nonce, plaintext, []byte("vault-base"))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt VaultBase: %w", err)
	}
	// nonce || ciphertext || tag
	result := make([]byte, 0, len(nonce)+len(encrypted))
	result = append(result, nonce...)
	result = append(result, encrypted...)
	return result, nil
}

// DecryptVaultBase decrypts VaultBase using the given info key and suite.
func DecryptVaultBase(ciphertext []byte, infoKey []byte, suite alg.Suite) (VaultBase, error) {
	if len(ciphertext) < alg.DefaultNonceLen+1 {
		return VaultBase{}, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:alg.DefaultNonceLen]
	encrypted := ciphertext[alg.DefaultNonceLen:]
	plaintext, err := suite.DecryptGCM(infoKey, nonce, encrypted, []byte("vault-base"))
	if err != nil {
		return VaultBase{}, fmt.Errorf("failed to decrypt VaultBase: %w", err)
	}
	var base VaultBase
	if err := json.Unmarshal(plaintext, &base); err != nil {
		return VaultBase{}, fmt.Errorf("failed to unmarshal VaultBase: %w", err)
	}
	return base, nil
}

// wrapRandomChunkKey generates a random chunkKey and wraps it with the suite AEAD
// using a wrapKey derived from dataKey + seq. Output: nonce || ciphertext+tag.
func wrapRandomChunkKey(dataKey []byte, suite alg.Suite, seq uint16) (chunkKey []byte, wrappedDek []byte, err error) {
	chunkKey = make([]byte, suite.KeyLen())
	if _, err = rand.Read(chunkKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random chunk key: %w", err)
	}

	wrapKey, err := alg.DeriveSubKey(dataKey, fmt.Sprintf("dek-wrap-%d", seq), uint32(suite.KeyLen()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive DEK wrapping key: %w", err)
	}

	nonce, err := suite.GenerateNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate DEK wrap nonce: %w", err)
	}

	aad := []byte(fmt.Sprintf("ry-dek-wrap-%d", seq))
	ct, err := suite.EncryptGCM(wrapKey, nonce, chunkKey, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	wrappedDek = make([]byte, 0, alg.DefaultNonceLen+len(ct))
	wrappedDek = append(wrappedDek, nonce...)
	wrappedDek = append(wrappedDek, ct...)
	return chunkKey, wrappedDek, nil
}

// unwrapChunkKey recovers a random chunkKey wrapped by the suite AEAD.
// Layout: nonce(DefaultNonceLen) || ciphertext+tag.
func unwrapChunkKey(dataKey []byte, suite alg.Suite, seq uint16, wrappedDek []byte) ([]byte, error) {
	if len(wrappedDek) <= alg.DefaultNonceLen {
		return nil, fmt.Errorf("wrapped DEK too short (%d bytes)", len(wrappedDek))
	}
	nonce := wrappedDek[:alg.DefaultNonceLen]
	ct := wrappedDek[alg.DefaultNonceLen:]

	wrapKey, err := alg.DeriveSubKey(dataKey, fmt.Sprintf("dek-wrap-%d", seq), uint32(suite.KeyLen()))
	if err != nil {
		return nil, fmt.Errorf("failed to derive DEK wrapping key: %w", err)
	}

	aad := []byte(fmt.Sprintf("ry-dek-wrap-%d", seq))
	chunkKey, err := suite.DecryptGCM(wrapKey, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("DEK wrap verification failed (wrong data key or tampered vault): %w", err)
	}
	return chunkKey, nil
}

// EncryptVaultItem encrypts a VaultItem and returns the wrapped DEK + ciphertext.
func EncryptVaultItem(item VaultItem, dataKey []byte, macKey []byte, suite alg.Suite, seq uint16) (VaultBlock, error) {
	chunkKey, wrappedDek, err := wrapRandomChunkKey(dataKey, suite, seq)
	if err != nil {
		return VaultBlock{}, err
	}

	plaintext, err := json.Marshal(item)
	if err != nil {
		return VaultBlock{}, fmt.Errorf("failed to marshal VaultItem: %w", err)
	}
	nonce, err := suite.GenerateNonce()
	if err != nil {
		return VaultBlock{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext, err := suite.EncryptGCM(chunkKey, nonce, plaintext, fmt.Appendf([]byte{}, "vault-block-%d", seq))
	if err != nil {
		return VaultBlock{}, fmt.Errorf("failed to encrypt VaultItem: %w", err)
	}
	fullCipher := make([]byte, 0, alg.DefaultNonceLen+len(ciphertext))
	fullCipher = append(fullCipher, nonce...)
	fullCipher = append(fullCipher, ciphertext...)

	block := VaultBlock{
		Seq:             seq,
		WrappedDekLen:   byte(len(wrappedDek)),
		WrappedDek:      wrappedDek,
		CipherLen:       uint16(len(fullCipher)),
		VaultItemCipher: fullCipher,
		MacLen:          byte(alg.DefaultMacLen),
	}
	computedMac, err := suite.ComputeMAC(macKey, append(util.Uint16ToBytes(seq), fullCipher...))
	if err != nil {
		return VaultBlock{}, fmt.Errorf("failed to compute block MAC: %w", err)
	}
	block.Mac = computedMac
	return block, nil
}

// DecryptVaultItem decrypts a VaultBlock back into VaultItem.
func DecryptVaultItem(block VaultBlock, macKey []byte, dataKey []byte, suite alg.Suite, expectedSeq uint16) (VaultItem, error) {
	// Verify block MAC first — cheapest integrity check, catches tampering early.
	dataForMAC := append(util.Uint16ToBytes(block.Seq), block.VaultItemCipher...)
	if !suite.VerifyMAC(macKey, dataForMAC, block.Mac) {
		return VaultItem{}, fmt.Errorf("block MAC verification failed for seq %d", block.Seq)
	}

	// Recover chunkKey from wrappedDek via suite AEAD unwrap.
	chunkKey, err := unwrapChunkKey(dataKey, suite, block.Seq, block.WrappedDek)
	if err != nil {
		return VaultItem{}, err
	}

	// Decrypt the ciphertext
	if len(block.VaultItemCipher) < alg.DefaultNonceLen+1 {
		return VaultItem{}, fmt.Errorf("ciphertext too short for block")
	}
	nonce := block.VaultItemCipher[:alg.DefaultNonceLen]
	ciphertext := block.VaultItemCipher[alg.DefaultNonceLen:]
	plaintext, err := suite.DecryptGCM(chunkKey, nonce, ciphertext, fmt.Appendf([]byte{}, "vault-block-%d", block.Seq))
	if err != nil {
		return VaultItem{}, fmt.Errorf("failed to decrypt VaultItem: %w", err)
	}

	var item VaultItem
	if err := json.Unmarshal(plaintext, &item); err != nil {
		return VaultItem{}, fmt.Errorf("failed to unmarshal VaultItem: %w", err)
	}

	if expectedSeq > 0 && block.Seq != expectedSeq {
		return item, nil
	}
	return item, nil
}

// MockVaultItemJSON generates a template JSON object ready for user filling.
func MockVaultItemJSON(category string) MockItem {
	return MockItem{
		Label:     "example-label",
		Category:  category,
		Account:   "user@example.com",
		Password:  "changeme666",
		BindEmail: "none",
		BindPhone: "none",
		Urls:      []string{"http://example.com"},
		Notes:     []string{"note 1"},
		OpeningAt: "2099/12/31",
	}
}

// ToVaultItem converts a MockItem to VaultItem with default history/category fields.
func ToVaultItem(m MockItem, category string) VaultItem {
	now := util.NowString()
	return VaultItem{
		Label:            strings.TrimSpace(m.Label),
		Category:         category,
		Account:          strings.TrimSpace(m.Account),
		Password:         m.Password,
		HistoryPasswords: []string{},
		BindEmail:        strings.TrimSpace(m.BindEmail),
		BindPhone:        strings.TrimSpace(m.BindPhone),
		Urls:             m.Urls,
		Notes:            m.Notes,
		OpeningAt:        strings.TrimSpace(m.OpeningAt),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// FromVaultItemToMock extracts user-editable fields from a VaultItem.
func FromVaultItemToMock(v VaultItem) MockItem {
	return MockItem{
		Label:     v.Label,
		Category:  v.Category,
		Account:   v.Account,
		Password:  v.Password,
		BindEmail: v.BindEmail,
		BindPhone: v.BindPhone,
		Urls:      v.Urls,
		Notes:     v.Notes,
		OpeningAt: v.OpeningAt,
	}
}
