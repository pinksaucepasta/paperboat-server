package machinealias

import "strings"

var reserved = map[string]bool{
	"api": true, "auth": true, "bugreport": true, "config": true, "connect": true,
	"doctor": true, "e2ee": true, "exec": true, "inbox": true, "internal": true,
	"login": true, "logout": true, "machine": true, "pb": true, "ping": true,
	"preview": true, "serve": true, "session": true, "sessions": true, "ssh": true,
	"status": true, "transfer": true, "wait": true, "www": true,
}

func Candidate(displayName string, ordinal int) string {
	base := normalize(displayName)
	if base == "" {
		base = "paperboat-machine"
	}
	if reserved[base] {
		base += "-machine"
	}
	suffix := ""
	if ordinal > 1 {
		suffix = "-" + decimal(ordinal)
	}
	if len(base)+len(suffix) > 63 {
		base = strings.TrimRight(base[:63-len(suffix)], "-")
	}
	return base + suffix
}

func Valid(value string) bool {
	if value == "" || len(value) > 63 || value != strings.ToLower(value) || value[0] == '-' || value[len(value)-1] == '-' || reserved[value] {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var result strings.Builder
	dash := false
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			result.WriteRune(character)
			dash = false
		} else if result.Len() > 0 && !dash {
			result.WriteByte('-')
			dash = true
		}
		if result.Len() == 63 {
			break
		}
	}
	return strings.Trim(result.String(), "-")
}

func decimal(value int) string {
	if value <= 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
