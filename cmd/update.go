package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	updateVault   string
	updateInput   string
	updateHistory bool
)

// updateCmd updates entries from a JSON file.
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing vault entries from a JSON file",
	Long: `Read a JSON file with updated entry data and update matching entries
in the vault (matched by label).

Use --his to keep the old password in HistoryPasswords when the password changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateVault == "" {
			return fmt.Errorf("--vault is required")
		}
		if updateInput == "" {
			return fmt.Errorf("--from is required")
		}
		vaultFile := util.VaultPath(updateVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}
		itemFile := util.JSONPath(updateInput)
		if !util.FileExists(itemFile) {
			return fmt.Errorf("input file %s not found", itemFile)
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.UpdateVaultItem(vaultFile, itemFile, passphrase, updateHistory)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

	updateCmd.Flags().StringVar(&updateVault, "vault", "", "Target vault name or file path (required)")
	updateCmd.Flags().StringVar(&updateInput, "from", "", "Input JSON file with updated entries (required)")
	updateCmd.Flags().BoolVar(&updateHistory, "his", false, "Keep old passwords in HistoryPasswords")
}
