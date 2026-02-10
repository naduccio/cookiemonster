package monster

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Spring Session / generic: base64(payload)--hex(HMAC-SHA256).
// Same idea as Symfony but we require base64 payload for detection.

type springParsedData struct {
	payload          []byte
	decodedSignature []byte
	parsed           bool
}

func (d *springParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}
	return fmt.Sprintf("Payload length: %d\nSignature: %x\n", len(d.payload), d.decodedSignature)
}

const (
	springDecoder   = "spring"
	springMinLength = 70
	springSigHexLen = 64
)

func springDecode(c *Cookie) bool {
	if len(c.raw) < springMinLength {
		return false
	}
	idx := strings.LastIndex(c.raw, "--")
	if idx < 0 {
		return false
	}
	payloadB64 := c.raw[:idx]
	sigHex := c.raw[idx+2:]
	if len(sigHex) != springSigHexLen {
		return false
	}
	decodedSig, err := hex.DecodeString(sigHex)
	if err != nil || len(decodedSig) != 32 {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil || len(payload) == 0 {
		return false
	}
	var parsedData springParsedData
	parsedData.payload = payload
	parsedData.decodedSignature = decodedSig
	parsedData.parsed = true
	c.wasDecodedBy(springDecoder, &parsedData)
	return true
}

func springUnsign(c *Cookie, secret []byte) bool {
	parsedData := c.parsedDataFor(springDecoder).(*springParsedData)
	computed := sha256HMAC(secret, parsedData.payload)
	return bytes.Equal(parsedData.decodedSignature, computed)
}
