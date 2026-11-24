package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	delVault  string
	delLabels string
	delPop    bool
)

// delCmd deletes entries from a vault.
var delCmd = &cobra.Command{
	Use:   "del",
	Short: "Delete entries from the vault by label",
	Long: `Delete one or more entries from the specified vault.
Use --pop to also export the deleted entries as <category>-<label>.json files.

Labels are comma-separated (e.g. "label1,label2,label3").`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if delVault == "" {
			return fmt.Errorf("--vault is required")
		}
		if delLabels == "" {
			return fmt.Errorf("--label is required")
		}
		vaultFile := util.VaultPath(delVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}

		labels := util.SplitAndTrim(delLabels, ",")
		if len(labels) == 0 {
			return fmt.Errorf("no valid labels provided")
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.DeleteVaultItem(vaultFile, labels, passphrase, delPop)
	},
}

func init() {
	rootCmd.AddCommand(delCmd)

	delCmd.Flags().StringVar(&delVault, "vault", "", "Target vault name or file path (required)")
	delCmd.Flags().StringVar(&delLabels, "label", "", "Comma-separated labels to delete (required)")
	delCmd.Flags().BoolVar(&delPop, "pop", false, "Also export deleted entries as JSON files")
}
