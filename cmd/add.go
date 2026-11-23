package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	addVault string
	addInput string
)

// addCmd adds entries from a JSON file to a vault.
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add one or more entries from a JSON file to the vault",
	Long: `Read a JSON file containing one or more vault entries and add them
to the specified vault (.sv file). The JSON can be a single object or an array.

Example JSON fields per entry:
  label, account, password, bindEmail, bindPhone, urls, notes, openingAt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if addVault == "" {
			return fmt.Errorf("--vault is required")
		}
		if addInput == "" {
			return fmt.Errorf("--in is required")
		}
		vaultFile := util.VaultPath(addVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}
		itemFile := util.JSONPath(addInput)
		if !util.FileExists(itemFile) {
			return fmt.Errorf("input file %s not found", itemFile)
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.SaveVaultItem(vaultFile, itemFile, passphrase)
	},
}

func init() {
	rootCmd.AddCommand(addCmd)

	addCmd.Flags().StringVar(&addVault, "vault", "", "Target vault name or file path (required)")
	addCmd.Flags().StringVar(&addInput, "in", "", "Input JSON file with entries (required)")
}
