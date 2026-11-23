package util

import (
	"encoding/binary"
	"fmt"
)

// Uint16ToBytes converts uint16 to 2-byte slice (big-endian).
func Uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

// Uint32ToBytes converts uint32 to 4-byte slice (big-endian).
func Uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// BytesToUint16 converts 2-byte slice to uint16 (big-endian).
func BytesToUint16(b []byte) (uint16, error) {
	if len(b) < 2 {
		return 0, fmt.Errorf("bytes too short for uint16: got %d, need 2", len(b))
	}
	return binary.BigEndian.Uint16(b[:2]), nil
}

// BytesToUint32 converts 4-byte slice to uint32 (big-endian).
func BytesToUint32(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("bytes too short for uint32: got %d, need 4", len(b))
	}
	return binary.BigEndian.Uint32(b[:4]), nil
}

// StringToBytes converts string to byte slice.
func StringToBytes(s string) []byte {
	return []byte(s)
}

// BytesToString converts byte slice to string.
func BytesToString(b []byte) string {
	return string(b)
}

// SumBytes returns the sum of multiple byte values as int.
func SumBytes(values ...byte) int {
	total := 0
	for _, v := range values {
		total += int(v)
	}
	return total
}

// SumLengths returns the sum of mixed-type length values as int.
func SumLengths(bytes []byte, uint16s []uint16, uint32s []uint32) int {
	total := 0
	for _, b := range bytes {
		total += int(b)
	}
	for _, u := range uint16s {
		total += int(u)
	}
	for _, u := range uint32s {
		total += int(u)
	}
	return total
}
