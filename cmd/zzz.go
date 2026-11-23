package cmd

import "github.com/spf13/cobra"

var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Generate the autocompletion script for the specified shell",
}

func init() {
	completionCmd.Hidden = true
	rootCmd.AddCommand(completionCmd)
}
