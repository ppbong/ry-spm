package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	mockVault string
	mockOut   string
)

// mockCmd generates a JSON template for vault entries.
var mockCmd = &cobra.Command{
	Use:   "mock",
	Short: "Generate a JSON template file for vault entries",
	Long: `Create a template JSON file pre-filled with example data,
using the vault's category. Fill in your real data and use "spm add" to import it.

Default output filename: mock-<category>.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mockVault == "" {
			return fmt.Errorf("--vault is required")
		}
		vaultFile := util.VaultPath(mockVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.MockVaultItem(vaultFile, mockOut, passphrase)
	},
}

func init() {
	rootCmd.AddCommand(mockCmd)

	mockCmd.Flags().StringVar(&mockVault, "vault", "", "Target vault name or file path (required)")
	mockCmd.Flags().StringVar(&mockOut, "out", "", "Output JSON file name (default: mock-<category>.json)")
}
