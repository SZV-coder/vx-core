package sub

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/5vnetwork/vx-core/app/configs"
)

type DecodeResult struct {
	Configs     []*configs.OutboundHandlerConfig
	Description string
	FailedNodes []string
}

// DecodeBase64 decodes a base64 string, trying both standard and URL-safe encoding
// and adding padding if necessary
func DecodeBase64(encoded string) (string, error) {
	// Add padding if necessary
	if len(encoded)%4 != 0 {
		padLen := 4 - len(encoded)%4
		encoded += strings.Repeat("=", padLen)
	}

	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// If that fails, try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			// Try URL-safe base64 with no padding
			decoded, err = base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				// Try standard base64 with no padding
				decoded, err = base64.RawStdEncoding.DecodeString(encoded)
				if err != nil {
					return "", fmt.Errorf("failed to decode base64 string: %w", err)
				}
			}
		}
	}
	return string(decoded), nil
}
