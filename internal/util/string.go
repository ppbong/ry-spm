package util

import (
	"regexp"
	"strings"
)

// TrimAll removes all leading and trailing whitespace from s.
func TrimAll(s string) string {
	return strings.TrimSpace(s)
}

// RemoveWhitespace removes all whitespace characters from s.
func RemoveWhitespace(s string) string {
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(s, "")
}

// JoinNonEmpty joins non-empty strings in the slice with the given separator.
func JoinNonEmpty(sep string, parts ...string) string {
	var filtered []string
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	return strings.Join(filtered, sep)
}

// SplitAndTrim splits s by sep and trims each resulting part.
func SplitAndTrim(s, sep string) []string {
	raw := strings.Split(s, sep)
	result := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ReplaceAll replaces all occurrences of old with new in s.
func ReplaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

// ToUpper converts s to uppercase.
func ToUpper(s string) string {
	return strings.ToUpper(s)
}

// ToLower converts s to lowercase.
func ToLower(s string) string {
	return strings.ToLower(s)
}

// ValidateIdentifier checks if s matches [A-Za-z0-9_-] and is within maxLen.
func ValidateIdentifier(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	re := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	return re.MatchString(s)
}

// ValidateIdentifierAlphaStart checks if s starts with a letter,
// contains only [A-Za-z0-9_-], and is within maxLen.
func ValidateIdentifierAlphaStart(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	re := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	return re.MatchString(s)
}

// ValidatePassphrase checks within maxLen.
func ValidatePassphrase(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	return true
}
