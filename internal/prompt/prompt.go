package prompt

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// errNoTerminal is returned when passphrase input is requested while stdin
// is not connected to an interactive terminal (piped or redirected).
var errNoTerminal = fmt.Errorf("passphrase input requires an interactive terminal — " +
	"command-line flags, environment variables, and stdin redirection are not allowed")

// isTerminal reports whether both stdin and stdout are connected to a TTY.
func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// ReadLine reads a line of text from stdin after printing the prompt.
func ReadLine(prompt string) (string, error) {
	if prompt != "" {
		fmt.Print(prompt)
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// ReadPassword reads a password from stdin without echoing.
//
// Security: this function refuses to run unless both stdin and stdout are
// connected to an interactive terminal. This prevents passphrases from being
// supplied via command-line flags, environment variables, stdin redirection
// ("echo pass | spm ...") or here-documents, all of which leave traces in
// shell history, process listings, or filesystem snapshots.
func ReadPassword(prompt string) (string, error) {
	if !isTerminal() {
		return "", errNoTerminal
	}
	if prompt != "" {
		fmt.Print(prompt)
	}
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return strings.TrimSpace(string(pwd)), nil
}

// ReadPasswordConfirm reads a password and asks for confirmation.
// Returns an error if the two inputs do not match.
func ReadPasswordConfirm(prompt, confirmPrompt string, minLen int) (string, error) {
	for {
		pwd, err := ReadPassword(prompt)
		if err != nil {
			return "", err
		}
		if minLen > 0 && len(pwd) < minLen {
			fmt.Printf("  Password must be at least %d characters.\n", minLen)
			continue
		}
		confirm, err := ReadPassword(confirmPrompt)
		if err != nil {
			return "", err
		}
		if pwd != confirm {
			fmt.Println("  Passwords do not match. Please try again.")
			continue
		}
		return pwd, nil
	}
}

// SelectAlgorithm prompts the user to choose between AES and SM4.
// Returns the chosen algorithm name.
func SelectAlgorithm(defaultAlg string) (string, error) {
	choices := "1) AES (AES-256-GCM)  2) SM4 (SM4-CTR+HMAC)\nChoose algorithm [1,2] (default 1): "
	for {
		input, err := ReadLine(choices)
		if err != nil {
			return "", err
		}
		if input == "" {
			if defaultAlg != "" {
				return defaultAlg, nil
			}
			return "AES", nil
		}
		switch strings.TrimSpace(input) {
		case "1", "AES", "aes":
			return "AES", nil
		case "2", "SM4", "sm4":
			return "SM4", nil
		default:
			fmt.Println("  Invalid choice. Please enter 1 or 2.")
		}
	}
}

// InputCategory prompts the user for a category name.
func InputCategory(defaultCategory string, maxLen int) (string, error) {
	prompt := fmt.Sprintf("Enter category [A-Za-z0-9_-] (default %s): ", defaultCategory)
	for {
		input, err := ReadLine(prompt)
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultCategory, nil
		}
		if !validateIdentifier(input, maxLen) {
			fmt.Printf("  Invalid category. Only [A-Za-z0-9_-] allowed, max length %d.\n", maxLen)
			continue
		}
		return input, nil
	}
}

// InputVaultName prompts the user for a vault name.
func InputVaultName(defaultVault string, maxLen int) (string, error) {
	prompt := fmt.Sprintf("Enter vault name [A-Za-z0-9_-] (default %s): ", defaultVault)
	for {
		input, err := ReadLine(prompt)
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultVault, nil
		}
		if !validateIdentifier(input, maxLen) {
			fmt.Printf("  Invalid vault name. Only [A-Za-z0-9_-] allowed, max length %d.\n", maxLen)
			continue
		}
		return input, nil
	}
}

// ReadPassphrase reads a single passphrase without confirmation.
func ReadPassphrase(label string) (string, error) {
	prompt := fmt.Sprintf("Enter %s passphrase: ", label)
	for {
		pwd, err := ReadPassword(prompt)
		if err != nil {
			return "", err
		}
		if pwd == "" {
			fmt.Println("  Passphrase cannot be empty.")
			continue
		}
		return pwd, nil
	}
}

// Confirm asks the user for a yes/no confirmation.
func Confirm(message string) bool {
	prompt := message + " [y/N]: "
	input, err := ReadLine(prompt)
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// InputGenericLine reads a generic line of text with a prompt and default value.
func InputGenericLine(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		prompt = fmt.Sprintf("%s (default %s): ", prompt, defaultValue)
	} else {
		prompt = prompt + ": "
	}
	input, err := ReadLine(prompt)
	if err != nil {
		return "", err
	}
	if input == "" {
		return defaultValue, nil
	}
	return input, nil
}

func validateIdentifier(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
