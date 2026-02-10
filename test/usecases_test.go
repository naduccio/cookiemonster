// Use-case tests: verifica che ogni decoder decodifichi e trovi la chiave corretta.
// Esegui con: go test -v ./test/

package test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

func wordlistWith(keys ...string) *monster.Wordlist {
	wl := monster.NewWordlist()
	entries := make([][]byte, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, []byte(k))
	}
	if err := wl.LoadFromArray(entries); err != nil {
		panic(err)
	}
	return wl
}

// --- CookieSignature (Node.js cookie-signature) ---
func signCookieSignature(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	b64 := base64.StdEncoding.EncodeToString(sig)
	// Node strips padding
	for len(b64) > 0 && b64[len(b64)-1] == '=' {
		b64 = b64[:len(b64)-1]
	}
	return payload + "." + b64
}

func TestUseCase_CookieSignature(t *testing.T) {
	secret := "my-secret"
	payload := "hello"
	value := signCookieSignature(payload, secret)

	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("CookieSignature: Decode() fallito")
	}
	wl := wordlistWith(secret, "wrong")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("CookieSignature: Unsign() non ha trovato la chiave")
	}
	if string(key) != secret {
		t.Errorf("CookieSignature: chiave trovata %q, atteso %q", key, secret)
	}
}

// --- Gorilla (Go securecookie signed) ---
func signGorilla(message []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(message)
	sig := mac.Sum(nil)
	combined := append(sig, message...)
	return base64.StdEncoding.EncodeToString(combined)
}

func TestUseCase_Gorilla(t *testing.T) {
	secret := "gorilla-secret"
	message := []byte(`{"user":"test"}`)
	value := signGorilla(message, secret)

	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Gorilla: Decode() fallito")
	}
	wl := wordlistWith(secret, "other")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Gorilla: Unsign() non ha trovato la chiave")
	}
	if string(key) != secret {
		t.Errorf("Gorilla: chiave trovata %q, atteso %q", key, secret)
	}
}

// --- Symfony (payload--hex(HMAC-SHA256)) ---
func signSymfony(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := mac.Sum(nil)
	return string(payload) + "--" + hex.EncodeToString(sig)
}

func TestUseCase_Symfony(t *testing.T) {
	secret := "symfony"
	payload := []byte("data=value")
	value := signSymfony(payload, secret)

	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Symfony: Decode() fallito")
	}
	wl := wordlistWith(secret, "wrong")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Symfony: Unsign() non ha trovato la chiave")
	}
	if string(key) != secret {
		t.Errorf("Symfony: chiave trovata %q, atteso %q", key, secret)
	}
}

// --- Spring (base64(payload)--hex(HMAC-SHA256)) ---
func signSpring(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := mac.Sum(nil)
	b64 := base64.StdEncoding.EncodeToString(payload)
	return b64 + "--" + hex.EncodeToString(sig)
}

func TestUseCase_Spring(t *testing.T) {
	secret := "spring"
	payload := []byte(`{"session":"abc"}`)
	value := signSpring(payload, secret)

	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Spring: Decode() fallito")
	}
	wl := wordlistWith(secret, "other")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Spring: Unsign() non ha trovato la chiave")
	}
	if string(key) != secret {
		t.Errorf("Spring: chiave trovata %q, atteso %q", key, secret)
	}
}

// --- Use case con vettori noti (decoder esistenti) ---

func TestUseCase_Django(t *testing.T) {
	// Vettore da pkg/monster/cookie_test.go (solo verifica Decode; chiave del vettore non nota)
	value := "gAJ9cQFVBV9uZXh0cQJYAQAAAC9zLg:1mh2IM:rAOWFyG5ROIOxriY8pwm9jFma5w"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Django: Decode() fallito")
	}
	// Unsign richiederebbe la chiave usata per firmare questo vettore (non pubblica)
}

func TestUseCase_Flask(t *testing.T) {
	value := "eyJjc3JmX3Rva2VuIjoiYjAxNDZjZGIzZGZiMTliYWM1N2EyNGU5M2U2YWVhNDdhOTNlNzVlZiJ9.YYN0SA.B5roVjMHOW3IYSrohS9FhgCFlHk"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Flask: Decode() fallito")
	}
	wl := wordlistWith("secret_key")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Flask: Unsign() non ha trovato la chiave")
	}
	if string(key) != "secret_key" {
		t.Errorf("Flask: chiave %q, atteso secret_key", key)
	}
}

func TestUseCase_JWT(t *testing.T) {
	value := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.O39wphnad2iRtKulTeEmBdPLz1s22_XihMtD7swLx_o"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("JWT: Decode() fallito")
	}
	wl := wordlistWith("changeme")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("JWT: Unsign() non ha trovato la chiave")
	}
	if string(key) != "changeme" {
		t.Errorf("JWT: chiave %q, atteso changeme", key)
	}
}

func TestUseCase_Rack(t *testing.T) {
	value := "BAhJIgl0ZXN0BjoGRVQ=--8c5ae09ed57f1e933cc466f5b99ea636d1fc31a2"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Rack: Decode() fallito")
	}
	wl := wordlistWith("super secret")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Rack: Unsign() non ha trovato la chiave")
	}
	if string(key) != "super secret" {
		t.Errorf("Rack: chiave %q, atteso super secret", key)
	}
}

func TestUseCase_Express(t *testing.T) {
	// session=payload^signature (base64url)
	value := "session=eyJhbmltYWxzIjoibGlvbiJ9^Vf2INocdJIqKWVfYGhXwPhQZNFI"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Express: Decode() fallito")
	}
	wl := wordlistWith("changeme")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Express: Unsign() non ha trovato la chiave")
	}
	if string(key) != "changeme" {
		t.Errorf("Express: chiave %q, atteso changeme", key)
	}
}

func TestUseCase_ItsDangerous(t *testing.T) {
	value := "WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("ItsDangerous: Decode() fallito")
	}
	wl := wordlistWith("secret-key")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("ItsDangerous: Unsign() non ha trovato la chiave")
	}
	if string(key) != "secret-key" {
		t.Errorf("ItsDangerous: chiave %q, atteso secret-key", key)
	}
}

func TestUseCase_Laravel(t *testing.T) {
	value := "eyJpdiI6IkJPV3Q1Q09OSGt3aitXbmZqdU5Fa2c9PSIsInZhbHVlIjoiVzVtWmlienduaHBWbEg2Mzh3SWFkTHFGWXVucDl3T0Z2SjA1cERQK0N1Zit5S0RyZzU3emxQTks2Q3VUWkl5RllyU3ljSGZScEpsUHhRTFgvaDVqa3lsOVY1WUZJQTJyM3gvMWRVN3BLSzVQQk12ZjJJcDhtdFo3MUR2WTdhajMiLCJtYWMiOiI3YjVmYTQ1ZjRjMjlhYTkzOTFhNWIxNjNlNjUyMzAxNDA1NWU4NDc0NGZjZGZjZGQ5NDUzMDhiYTRiZjI0NzYyIiwidGFnIjoiIn0%3D"
	c := monster.NewCookie(value)
	if !c.Decode() {
		t.Fatal("Laravel: Decode() fallito")
	}
	wl := wordlistWith("zseMzUq8M6oPB5xkPvIWddeepxzseJtN")
	key, ok := c.Unsign(wl, 10)
	if !ok {
		t.Fatal("Laravel: Unsign() non ha trovato la chiave")
	}
	if string(key) != "zseMzUq8M6oPB5xkPvIWddeepxzseJtN" {
		t.Errorf("Laravel: chiave errata")
	}
}
