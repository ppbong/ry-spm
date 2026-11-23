package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileExists checks if a file exists at the given path.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && !info.IsDir()
}

// DirectoryExists checks if a directory exists at the given path.
func DirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.IsDir()
}

// EnsureDirectory creates the directory (and parents) if it does not exist.
func EnsureDirectory(path string) error {
	if DirectoryExists(path) {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}

// IsFile checks if path points to a regular file.
func IsFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// IsDirectory checks if path points to a directory.
func IsDirectory(path string) bool {
	return DirectoryExists(path)
}

// GetFileName returns the base file name from a path.
func GetFileName(path string) string {
	return filepath.Base(path)
}

// GetFileStem returns the file name without extension.
func GetFileStem(path string) string {
	name := filepath.Base(path)
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext)
}

// GetFileExt returns the file extension including the dot.
func GetFileExt(path string) string {
	return filepath.Ext(path)
}

// BuildFilePath constructs a file path from directory and name.
func BuildFilePath(dir, name string) string {
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}

// MakeAbsPath converts a relative path to absolute using current working directory.
func MakeAbsPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	return filepath.Join(cwd, path), nil
}

// WriteFile writes content to path, creating or overwriting the file.
func WriteFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDirectory(dir); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	return os.WriteFile(path, content, 0o600)
}

// WriteFileAtomic writes content to path atomically: it first writes to a
// temp file in the same directory, then renames it over the target. This
// prevents vault corruption if the process is killed mid-write.
func WriteFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDirectory(dir); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to set temp file permissions: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	cleanup = false
	return nil
}

// ReadFile reads and returns the content of the file at path.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// TempFile creates a temporary file with the given prefix and returns its path.
func TempFile(prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix+"-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer f.Close()
	return f.Name(), nil
}

// DeleteFile removes the file at path if it exists.
func DeleteFile(path string) error {
	if !FileExists(path) {
		return nil
	}
	return os.Remove(path)
}

// CopyFile copies src to dst.
func CopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}
	return WriteFile(dst, data)
}

// VaultPath returns the vault file path for the given vault name.
func VaultPath(vault string) string {
	if strings.HasSuffix(vault, ".sv") {
		return vault
	}
	return vault + ".sv"
}

// JSONPath returns the json file path for the given base name.
func JSONPath(name string) string {
	if strings.HasSuffix(name, ".json") {
		return name
	}
	return name + ".json"
}
