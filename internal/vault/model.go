package vault

import "github.com/ppbong/ry-spm/internal/alg"

// mock item
type MockItem struct {
	Label     string   `json:"label"`
	Category  string   `json:"category"`
	Account   string   `json:"account"`
	Password  string   `json:"password"`
	BindEmail string   `json:"bindEmail"`
	BindPhone string   `json:"bindPhone"`
	Urls      []string `json:"urls"`
	Notes     []string `json:"notes"`
	OpeningAt string   `json:"openingAt"`
}

// vault item
type VaultItem struct {
	Label            string   `json:"label"`
	Category         string   `json:"category"`
	Account          string   `json:"account"`
	Password         string   `json:"password"`
	HistoryPasswords []string `json:"historyPasswords"`
	BindEmail        string   `json:"bindEmail"`
	BindPhone        string   `json:"bindPhone"`
	Urls             []string `json:"urls"`
	Notes            []string `json:"notes"`
	OpeningAt        string   `json:"openingAt"`
	CreatedAt        string   `json:"createdAt"`
	UpdatedAt        string   `json:"updatedAt"`
}

// vault base
type VaultBase struct {
	Tag      string   `json:"tag"`
	AlgName  string   `json:"algName"`
	KdfName  string   `json:"kdfName"`
	Category string   `json:"category"`
	Labels   []string `json:"labels"`
}

// vault header
type VaultHeader struct {
	BaseLen    uint8
	BaseCipher []byte
	AlgId      byte
	KdfId      byte
	KdfParamM  uint32
	KdfParamT  byte
	KdfParamP  byte
	SaltLen    uint8
	Salt       []byte
	MacLen     uint8
	Mac        []byte
	Count      uint32
	NextSeq    uint32
	CreatedAt  string
	UpdatedAt  string
	LastUsedAt string
}

// vault block
type VaultBlock struct {
	Seq             uint16
	WrappedDekLen   uint8
	WrappedDek      []byte
	CipherLen       uint16
	VaultItemCipher []byte
	MacLen          uint8
	Mac             []byte
}

// vault body
type VaultBody struct {
	Blocks []VaultBlock
}

// vault file
type VaultFile struct {
	Magic   string
	Version string
	Header  VaultHeader
	Body    VaultBody
	Trailer string
}

// VaultHandle holds the loaded vault state with derived keys and file content.
type VaultHandle struct {
	FilePath      string
	SingletonPass string
	AlgSuite      alg.Suite
	KdfParams     alg.KDFParams
	RootKey       []byte
	InfoKey       []byte
	DataKey       []byte
	MacKey        []byte
	Header        VaultHeader
	Base          VaultBase
	BaseDecrypted bool
	BodyBlocks    []VaultBlock
}
