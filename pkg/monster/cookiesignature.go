package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// Node.js cookie-signature (npm): value + '.' + base64(HMAC-SHA256(secret, value)).
// Uses last '.' to split payload and signature.

type cookiesignatureParsedData struct {
	payload          string
	signature        string
	decodedSignature []byte
	parsed           bool
}

func (d *cookiesignatureParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}
	return fmt.Sprintf("Payload: %s\nSignature: %s\n", d.payload, d.signature)
}

const (
	cookiesignatureDecoder   = "cookiesignature"
	cookiesignatureMinLength = 10
	cookiesignatureSigLen   = 32 // SHA256
)

func cookiesignatureDecode(c *Cookie) bool {
	if len(c.raw) < cookiesignatureMinLength {
		return false
	}
	// Only one dot: avoid collision with Flask (data.timestamp.sig) and JWT (h.b.s)
	if strings.Count(c.raw, ".") != 1 {
		return false
	}
	idx := strings.Index(c.raw, ".")
	if idx <= 0 || idx == len(c.raw)-1 {
		return false
	}
	payload := c.raw[:idx]
	sigB64 := c.raw[idx+1:]
	decoded, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(sigB64)
		if err != nil {
			return false
		}
	}
	if len(decoded) != cookiesignatureSigLen {
		return false
	}
	var parsedData cookiesignatureParsedData
	parsedData.payload = payload
	parsedData.signature = sigB64
	parsedData.decodedSignature = decoded
	parsedData.parsed = true
	c.wasDecodedBy(cookiesignatureDecoder, &parsedData)
	return true
}

func cookiesignatureUnsign(c *Cookie, secret []byte) bool {
	parsedData := c.parsedDataFor(cookiesignatureDecoder).(*cookiesignatureParsedData)
	computed := sha256HMAC(secret, []byte(parsedData.payload))
	return bytes.Equal(parsedData.decodedSignature, computed)
}
