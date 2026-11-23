// Package main is the entry point of the ry-spm (Secure Password Manager) CLI.
//
// ry-spm encrypts credentials into a single portable .sv vault file using
// AES-256-GCM or SM4 with Argon2id/PBKDF2 key derivation.
package main

import "github.com/ppbong/ry-spm/cmd"

func main() {
	cmd.Execute()
}
