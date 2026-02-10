package monster

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Symfony / Play / generic signed cookie: payload--hex(SHA256-HMAC).
// Payload can be raw or base64. Signature is 64 hex chars.

type symfonyParsedData struct {
	payload          []byte
	decodedSignature []byte
	parsed           bool
}

func (d *symfonyParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}
	return fmt.Sprintf("Payload length: %d\nSignature: %x\n", len(d.payload), d.decodedSignature)
}

const (
	symfonyDecoder   = "symfony"
	symfonyMinLength = 70 // 64 hex + "--" + minimal payload
	symfonySigHexLen = 64
)

func symfonyDecode(c *Cookie) bool {
	if len(c.raw) < symfonyMinLength {
		return false
	}
	idx := strings.Index(c.raw, "--")
	if idx < 0 {
		return false
	}
	payloadStr := c.raw[:idx]
	sigHex := c.raw[idx+2:]
	if len(sigHex) != symfonySigHexLen {
		return false
	}
	decodedSig, err := hex.DecodeString(sigHex)
	if err != nil || len(decodedSig) != 32 {
		return false
	}
	var payload []byte
	if decoded, err := base64.StdEncoding.DecodeString(payloadStr); err == nil && len(decoded) > 0 {
		payload = decoded
	} else {
		payload = []byte(payloadStr)
	}
	var parsedData symfonyParsedData
	parsedData.payload = payload
	parsedData.decodedSignature = decodedSig
	parsedData.parsed = true
	c.wasDecodedBy(symfonyDecoder, &parsedData)
	return true
}

func symfonyUnsign(c *Cookie, secret []byte) bool {
	parsedData := c.parsedDataFor(symfonyDecoder).(*symfonyParsedData)
	computed := sha256HMAC(secret, parsedData.payload)
	return bytes.Equal(parsedData.decodedSignature, computed)
}
