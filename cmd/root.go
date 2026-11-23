package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
// Commands:
//
//	init     Initialize a new vault (.sv file)
//	mock     Generate a JSON template for vault entries
//	add      Add one or more entries from a JSON file to the vault
//	del      Delete entries by label (optionally export them first)
//	pop      Extract entries by label without deleting them
//	update   Update existing entries from a JSON file
//	info     Show vault metadata (category, algorithm, labels, etc.)
//	show     Show decrypted entry details (plaintext passwords)
//	version  Show version info
var rootCmd = &cobra.Command{
	Use:   "spm",
	Short: "Secure Password Manager - a single-file encrypted password vault",
	Long: `spm (Secure Password Manager) is a single-file password vault CLI.
It uses AES-256-GCM or SM4 with Argon2id/PBKDF2 KDF to encrypt your credentials into a portable .sv file.`,
	SilenceUsage:  true, // print usage when error if
	SilenceErrors: true, // print twice error info if false
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
