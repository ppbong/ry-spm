package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppbong/ry-spm/internal/prompt"
	"github.com/ppbong/ry-spm/internal/util"
	"github.com/ppbong/ry-spm/internal/vault"
)

var (
	infoVault string
)

// infoCmd displays vault metadata.
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show vault metadata (algorithm, category, labels, etc.)",
	Long: `Display metadata about a vault file.

If no passphrase or incorrect passphrase is given, only public metadata is shown.
With a correct passphrase, decrypted info including category and labels is also shown.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if infoVault == "" {
			return fmt.Errorf("--vault is required")
		}
		vaultFile := util.VaultPath(infoVault)
		if !util.FileExists(vaultFile) {
			return fmt.Errorf("vault file %s not found", vaultFile)
		}

		passphrase, err := prompt.ReadPassphrase("master")
		if err != nil {
			return err
		}

		return vault.ShowVaultInfo(vaultFile, passphrase)
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)

	infoCmd.Flags().StringVar(&infoVault, "vault", "", "Target vault name or file path (required)")
}
