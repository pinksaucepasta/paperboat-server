package previewtunnelapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const maxSafeMetadataBytes = 32 << 10

var forbiddenMetadataKeys = map[string]struct{}{
	"accesstoken": {}, "apikey": {}, "authorization": {}, "clientsecret": {},
	"cookie": {}, "headers": {}, "password": {}, "privatekey": {}, "refreshtoken": {},
	"requestbody": {}, "requestheaders": {}, "responsebody": {}, "responseheaders": {},
	"secret": {}, "sessiontoken": {}, "setcookie": {}, "token": {},
}

// SafeMetadata rejects unsafe audit metadata at construction. Credential
// references and thumbprints remain allowed because they are not credentials.
func SafeMetadata(metadata map[string]any) (map[string]any, error) {
	if metadata == nil {
		return map[string]any{}, nil
	}
	copy, err := safeValue(metadata)
	if err != nil {
		return nil, err
	}
	result := copy.(map[string]any)
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxSafeMetadataBytes {
		return nil, fmt.Errorf("%w: metadata must be valid JSON and at most %d bytes", ErrUnsafeMetadata, maxSafeMetadataBytes)
	}
	return result, nil
}

func safeValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if _, forbidden := forbiddenMetadataKeys[normalized]; forbidden {
				return nil, fmt.Errorf("%w: field %q is forbidden", ErrUnsafeMetadata, key)
			}
			safe, err := safeValue(child)
			if err != nil {
				return nil, err
			}
			result[key] = safe
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			safe, err := safeValue(child)
			if err != nil {
				return nil, err
			}
			result[index] = safe
		}
		return result, nil
	case string:
		upper := strings.ToUpper(typed)
		if strings.Contains(upper, "BEARER ") || strings.Contains(upper, "BEGIN PRIVATE KEY") ||
			strings.Contains(upper, "PASSWORD=") || strings.Contains(upper, "TOKEN=") ||
			strings.Contains(upper, "AUTHORIZATION=") || strings.Contains(upper, "AUTHORIZATION:") {
			return nil, fmt.Errorf("%w: credential-like value is forbidden", ErrUnsafeMetadata)
		}
		if err := rejectCredentialURLs(typed); err != nil {
			return nil, err
		}
		return typed, nil
	case nil, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return typed, nil
	default:
		return nil, fmt.Errorf("%w: unsupported value type %T", ErrUnsafeMetadata, value)
	}
}

func rejectCredentialURLs(value string) error {
	candidates := append([]string{value}, strings.Fields(value)...)
	for _, raw := range candidates {
		candidate := strings.Trim(raw, "\"'()[]{}<>,.;")
		if !strings.Contains(candidate, "://") {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || !parsed.IsAbs() {
			continue
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: URL user information is forbidden", ErrUnsafeMetadata)
		}
		for key := range parsed.Query() {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if _, forbidden := forbiddenMetadataKeys[normalized]; forbidden {
				return fmt.Errorf("%w: URL credential parameter is forbidden", ErrUnsafeMetadata)
			}
		}
	}
	return nil
}
