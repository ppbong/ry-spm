package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	showVault  string
	showLabels string
)

// showCmd displays decrypted entry details including plaintext passwords.
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show full details of vault entries (including plaintext passwords)",
	Long: `Decrypt and print one or more vault entries with all fields,
including the plaintext password. If --label is omitted, all entries are shown.

Labels are comma-separated (e.g. "label1,label2,label3").`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVault == "" {
			return fmt.Errorf("--vault is required")
		}
		vaultFile := util.VaultPath(showVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}

		var labels []string
		if showLabels != "" {
			labels = util.SplitAndTrim(showLabels, ",")
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.ShowVaultItemDetail(vaultFile, labels, passphrase)
	},
}

func init() {
	rootCmd.AddCommand(showCmd)

	showCmd.Flags().StringVar(&showVault, "vault", "", "Target vault name or file path (required)")
	showCmd.Flags().StringVar(&showLabels, "label", "", "Comma-separated labels to show (all if empty)")
}
