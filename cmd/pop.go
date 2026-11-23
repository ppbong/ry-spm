package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	popVault  string
	popLabels string
)

// popCmd extracts entries from a vault without deleting them.
var popCmd = &cobra.Command{
	Use:   "pop",
	Short: "Extract entries from the vault as JSON files (without deleting)",
	Long: `Export one or more entries from the vault as <label>.json files
in the current directory, without removing them from the vault.

Labels are comma-separated (e.g. "label1,label2,label3").`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if popVault == "" {
			return fmt.Errorf("--vault is required")
		}
		if popLabels == "" {
			return fmt.Errorf("--label is required")
		}
		vaultFile := util.VaultPath(popVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}

		labels := util.SplitAndTrim(popLabels, ",")
		if len(labels) == 0 {
			return fmt.Errorf("no valid labels provided")
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.ExtractVaultItem(vaultFile, labels, passphrase)
	},
}

func init() {
	rootCmd.AddCommand(popCmd)

	popCmd.Flags().StringVar(&popVault, "vault", "", "Target vault name or file path (required)")
	popCmd.Flags().StringVar(&popLabels, "label", "", "Comma-separated labels to extract (required)")
}
