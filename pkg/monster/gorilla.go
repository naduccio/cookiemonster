package monster

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// Gorilla Securecookie (Go) signed-only: base64( HMAC-SHA256(secret, message) || message ).
// First 32 bytes after decode are the MAC, rest is the message.

type gorillaParsedData struct {
	message   []byte
	storedMAC []byte
	parsed    bool
}

func (d *gorillaParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}
	return fmt.Sprintf("Message length: %d\nMAC length: %d\n", len(d.message), len(d.storedMAC))
}

const (
	gorillaDecoder   = "gorilla"
	gorillaMinLength = 44 // 32 bytes MAC base64 + minimal message
	gorillaMACLen    = 32
)

func gorillaDecode(c *Cookie) bool {
	if len(c.raw) < gorillaMinLength {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(c.raw)
	if err != nil {
		return false
	}
	if len(decoded) <= gorillaMACLen {
		return false
	}
	var parsedData gorillaParsedData
	parsedData.storedMAC = decoded[:gorillaMACLen]
	parsedData.message = decoded[gorillaMACLen:]
	parsedData.parsed = true
	c.wasDecodedBy(gorillaDecoder, &parsedData)
	return true
}

func gorillaUnsign(c *Cookie, secret []byte) bool {
	parsedData := c.parsedDataFor(gorillaDecoder).(*gorillaParsedData)
	computed := sha256HMAC(secret, parsedData.message)
	return bytes.Equal(parsedData.storedMAC, computed)
}
