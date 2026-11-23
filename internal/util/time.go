package util

import (
	"fmt"
	"time"
)

const (
	DateFormatSlash     = "2006/01/02"
	DateFormatDash      = "2006-01-02"
	DateTimeFormatSlash = "2006/01/02 15:04:05"
	DateTimeFormatDash  = "2006-01-02 15:04:05"
	DefaultFormat       = DateTimeFormatDash
)

// Now returns the current local time.
func Now() time.Time {
	return time.Now()
}

// NowString returns the current time formatted with DefaultFormat.
func NowString() string {
	return time.Now().Format(DefaultFormat)
}

// FormatTime formats t using the given layout.
func FormatTime(t time.Time, layout string) string {
	return t.Format(layout)
}

// ParseTime parses a time string using the given layout.
func ParseTime(s, layout string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}
	return time.ParseInLocation(layout, s, time.Local)
}

// ParseAnyFormat tries multiple layouts to parse a time string.
func ParseAnyFormat(s string) (time.Time, error) {
	layouts := []string{
		DateTimeFormatDash,
		DateTimeFormatSlash,
		DateFormatDash,
		DateFormatSlash,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := ParseTime(s, layout); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse time: %s", s)
}

// IsExpired checks if t is older than maxAge.
func IsExpired(t time.Time, maxAge time.Duration) bool {
	if t.IsZero() {
		return true
	}
	return time.Since(t) > maxAge
}

// DaysSince returns the number of days since t.
func DaysSince(t time.Time) int {
	if t.IsZero() {
		return -1
	}
	return int(time.Since(t).Hours() / 24)
}

// IsOverdueForBackup returns true if t is older than 90 days (3 months).
func IsOverdueForBackup(t time.Time) bool {
	maxAge := 90 * 24 * time.Hour
	return IsExpired(t, maxAge)
}
