package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

var (
	client = http.Client{
		Timeout: time.Second * 10,

		// We do not verify TLS certificates for ease of use, although we could
		// make this configurable in the future.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		// Follow redirects (default: up to 10).
	}
)

func buildCookieMap(res *http.Response) map[string]*http.Cookie {
	cookieMap := make(map[string]*http.Cookie)

	for _, cookie := range res.Cookies() {
		cookieMap[cookie.Name] = cookie
	}

	return cookieMap
}

// currentURL is set by handleURL so that on success we can return key instead of exiting (URL mode).
var currentURL string

// hit holds a successful result: URL, vulnerable cookie string, discovered key, and decoder that matched.
type hit struct {
	url     string
	cookie  string
	key     []byte
	decoder string
}

// checkCookie tries to unsign the cookie; returns (key, found, decoder) in URL mode, else exits in cookie mode.
// cookieDisplay is the string to show in logs (e.g. "name=value").
func checkCookie(wl *monster.Wordlist, value string, cookieDisplay string) (key []byte, found bool, decoder string) {
	c := monster.NewCookie(value)

	if !c.Decode() {
		return nil, false, ""
	}

	// In modalità URL non stampare il report dei decoder (Message length, MAC length, ecc.)
	if *verboseFlag && currentURL == "" {
		fmt.Println(c.String())
	}

	gotKey, success := c.Unsign(wl, uint64(*concurrencyFlag))
	if !success {
		if *verboseFlag {
			for _, dec := range c.DecodedDecoders() {
				fmt.Printf("%sTecnologia: %s | URL: %s | Cookie: %s | ma nessuna chiave ha funzionato.%s\n", ColorYellow, dec, currentURL, cookieDisplay, ColorReset)
			}
		}
		return nil, false, ""
	}

	if currentURL != "" {
		_, _, dec := c.Result()
		return gotKey, true, dec
	}
	keyDiscoveredMessage(c)
	handleResign(c)
	os.Exit(0)
	return nil, false, "" // unreachable
}

// getURL performs a GET with Chrome User-Agent and follows redirects.
func getURL(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", chromeUserAgent)
	return client.Do(req)
}

// normalizeURL adds https:// if the string has no scheme.
func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return "https://" + s
	}
	return s
}

// collectURLs returns the list of URLs: from -url (if set), then args, then stdin.
func collectURLs() []string {
	var list []string
	if *urlFlag != "" {
		list = append(list, normalizeURL(*urlFlag))
	}
	for _, a := range flag.Args() {
		if u := normalizeURL(a); u != "" {
			list = append(list, u)
		}
	}
	// Always read URLs from stdin (one per line)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		if u := normalizeURL(sc.Text()); u != "" {
			list = append(list, u)
		}
	}
	return list
}

func formatKey(key []byte) string {
	if isASCII(string(key)) {
		return string(key)
	}
	return base64Key(key)
}

const clearLine = "\r\033[K"

func handleURL() {
	urls := collectURLs()
	if len(urls) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var lastErr error
	var totalCookies int
	var hits []hit
	total := len(urls)
	statusCount := make(map[int]int) // codice HTTP -> numero di URL

	for i, rawURL := range urls {
		pct := 0
		if total > 0 {
			pct = (i * 100) / total
		}
		fmt.Fprintf(os.Stderr, "%s%d%% (%d/%d URL)", clearLine, pct, i+1, total)

		currentURL = rawURL
		res, err := getURL(rawURL)
		if err != nil {
			lastErr = err
			statusCount[0]++ // 0 = richiesta fallita (nessun codice HTTP)
			continue
		}
		statusCount[res.StatusCode]++
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()

		cookies := res.Cookies()
		totalCookies += len(cookies)

		if len(cookies) == 0 {
			continue
		}

		wl := loadWordlist()
		cookieMap := buildCookieMap(res)

		for _, cookie := range cookies {
			value := strings.TrimSpace(cookie.Value)
			sibling, hasSibling := cookieMap[cookie.Name+".sig"]

			if hasSibling {
				name := strings.TrimSpace(cookie.Name)
				cookieStr := name + "=" + value + "^" + sibling.Value
				input := name + "=" + value + "^" + sibling.Value
				if key, found, dec := checkCookie(wl, input, cookieStr); found {
					hits = append(hits, hit{rawURL, cookieStr, key, dec})
				}
			}

			cookieStr := cookie.Name + "=" + value
			if key, found, dec := checkCookie(wl, value, cookieStr); found {
				hits = append(hits, hit{rawURL, cookieStr, key, dec})
			}
		}
	}

	// 100% e nuova riga così l'output dei risultati non si attacca alla barra
	fmt.Fprintf(os.Stderr, "%s100%% (%d/%d URL)\n", clearLine, total, total)

	printStatusStats(statusCount, total)

	if lastErr != nil && totalCookies == 0 {
		os.Exit(1)
	}

	if len(hits) == 0 {
		fmt.Println("Nessun risultato.")
		os.Exit(1)
	}

	for _, h := range hits {
		fmt.Println(h.url)
		fmt.Printf("%sDecoder: %s%s\n", ColorGreen, h.decoder, ColorReset)
		fmt.Println("Cookie:", h.cookie)
		fmt.Println("Key:", formatKey(h.key))
	}
	os.Exit(0)
}

// printStatusStats stampa su stderr le statistiche per codice HTTP.
func printStatusStats(statusCount map[int]int, total int) {
	if len(statusCount) == 0 {
		return
	}
	var codes []int
	for code := range statusCount {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	fmt.Fprintln(os.Stderr, "--- Statistiche HTTP ---")
	for _, code := range codes {
		n := statusCount[code]
		label := fmt.Sprintf("%d", code)
		if code == 0 {
			label = "errore (nessuna risposta)"
		}
		fmt.Fprintf(os.Stderr, "  %s: %d (%.1f%%)\n", label, n, float64(n)/float64(total)*100)
	}
	fmt.Fprintf(os.Stderr, "  Totale: %d URL\n", total)
}
