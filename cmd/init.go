package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	initAlg      string
	initCategory string
	initVault    string
	initKDF      string
)

// initCmd initializes a new vault file.
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new .sv vault file",
	Long: `Create a new encrypted vault file (.sv) in the current directory.

You will be prompted for:
  - Algorithm   : AES (default) or SM4
  - Category    : logical group name (max 32 chars, [A-Za-z0-9_-])
  - Vault name  : file name without extension (default = category, max 64 chars)
  - Passphrase  : used to derive root key -> data keys + mac keys (max 64 chars)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		algName := initAlg
		if algName == "" {
			var err error
			algName, err = prompt.SelectAlgorithm("AES")
			if err != nil {
				return err
			}
		}

		category := initCategory
		if category == "" {
			var err error
			category, err = prompt.InputCategory("", 32)
			if err != nil {
				return err
			}
		}
		if !util.ValidateIdentifier(category, 32) {
			return fmt.Errorf("invalid category: %q", category)
		}

		vaultName := initVault
		if vaultName == "" {
			var err error
			vaultName, err = prompt.InputVaultName(category, 64)
			if err != nil {
				return err
			}
		}
		if !util.ValidateIdentifier(vaultName, 64) {
			return fmt.Errorf("invalid vault name: %q", vaultName)
		}

		passphrase, err := prompt.ReadPasswordConfirm(
			"Master passphrase: ",
			"Confirm master passphrase: ",
			4,
		)
		if err != nil {
			return err
		}

		kdfName := initKDF
		if kdfName == "" {
			kdfName = "Argon2id"
		}

		return vault.Initialize(algName, category, vaultName, passphrase, kdfName)
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&initAlg, "alg", "", "Encryption algorithm: AES or SM4 (interactive if empty)")
	initCmd.Flags().StringVar(&initCategory, "category", "", "Category name [A-Za-z0-9_-] (interactive if empty)")
	initCmd.Flags().StringVar(&initVault, "vault", "", "Vault file name [A-Za-z0-9_-] (interactive if empty, default = category)")
	initCmd.Flags().StringVar(&initKDF, "kdf", "", "Key derivation: Argon2id or PBKDF2 (default Argon2id)")
}
