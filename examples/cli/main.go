// Package main provides a CLI example for interacting with the authservice.
//
// Usage:
//
//	authcli -s http://localhost:8080 login user pass
//	authcli -s http://localhost:8080 me
//	authcli -s http://localhost:8080 tokens list
//	authcli -s http://localhost:8080 tokens create -d "my-app"
//	authcli -s http://localhost:8080 tokens revoke <client-id>
//
// Credentials are cached in ~/.authservice/creds.json.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flag.CommandLine = flag.NewFlagSet("authcli", flag.ExitOnError)
	server := flag.String("s", "", "authserver base URL (e.g. http://localhost:8080)")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "error: -s <base-url> is required")
		return 1
	}

	subcmd := flag.Arg(0)
	allArgs := flag.Args()
	var subArgs []string
	if len(allArgs) > 1 {
		subArgs = allArgs[1:]
	}

	switch subcmd {
	case "login":
		return cmdLogin(*server, subArgs)
	case "me":
		return cmdMe(*server)
	case "tokens":
		return cmdTokens(*server, subArgs)
	case "help", "":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", subcmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: authcli -s <base-url> <command> [args]

Commands:
  login <username> <password>   Authenticate and save credentials
  me                            Show current user profile
  tokens list                   List OAuth client tokens
  tokens create -d <domain>     Create a new OAuth client token
  tokens revoke <client-id>     Delete an OAuth client token`)
}

// ---------- creds cache ----------

const credsDir = ".authservice"
const credsFile = "creds.json"

// Creds holds the cached session cookie.
type Creds struct {
	SessionCookie string `json:"session_cookie"`
	CreatedAt     string `json:"created_at"`
}

func loadCreds() (*Creds, error) {
	p, err := credsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Creds
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("bad credentials file: %w", err)
	}
	return &c, nil
}

func saveCreds(cookie string) error {
	p, err := credsPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(Creds{
		SessionCookie: cookie,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

func credsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, credsDir, credsFile), nil
}

// ---------- HTTP helpers ----------

func httpClient(cookies []*http.Cookie) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("too many redirects")
			}
			for _, c := range cookies {
				req.AddCookie(c)
			}
			return nil
		},
	}
}

func request(ctx context.Context, client *http.Client, method, baseURL, path string, body io.Reader) (*http.Response, error) {
	u := baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

// readResp reads the response body, closes the body, and returns the raw bytes.
// It returns (nil, nil) on success (non-4xx), or (nil, fmt.Errorf(...)) on error.
// On HTTP 4xx, it returns the body bytes with an error so callers can report the message.
func readResp(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// findSessionCookie extracts the first "session*" cookie from the response
// headers by using the standard library's Set-Cookie parser.
func findSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "session") {
			return c
		}
	}
	return nil
}

// ---------- login command ----------

func cmdLogin(baseURL string, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "error: usage: authcli -s <url> login <username> <password>")
		return 1
	}
	username, password := args[0], args[1]

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	resp, err := httpClient(nil).Post(baseURL+"/login", "application/x-www-form-urlencoded", bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: login request failed: %v\n", err)
		return 1
	}
	// Read and discard response body; we only need the session cookie.
	if _, err := readResp(resp); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Extract session cookie from response.
	ck := findSessionCookie(resp)
	if ck == nil {
		fmt.Fprintln(os.Stderr, "error: no session cookie returned")
		return 1
	}
	cookie := ck.Name + "=" + ck.Value

	if err := saveCreds(cookie); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save credentials: %v\n", err)
	}
	fmt.Printf("Authenticated as %s\n", username)
	return 0
}

// ---------- me command ----------

func cmdMe(baseURL string) int {
	creds, err := loadCreds()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: no credentials found. Run 'authcli login' first.")
		return 1
	}

	client := httpClient(parseCookieString(creds.SessionCookie))

	resp, err := request(context.Background(), client, http.MethodGet, baseURL, "/userinfo", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		return 1
	}
	body, err := readResp(resp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var out bytes.Buffer
	json.Indent(&out, body, "", "  ")
	fmt.Println(out.String())
	return 0
}

// ---------- tokens command ----------

func cmdTokens(baseURL string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: usage: authcli -s <url> tokens <list|create|revoke> [args]")
		return 1
	}

	creds, err := loadCreds()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: no credentials found. Run 'authcli login' first.")
		return 1
	}

	client := httpClient(parseCookieString(creds.SessionCookie))

	subcmd := args[0]
	switch subcmd {
	case "list":
		return cmdTokensList(baseURL, client)
	case "create":
		return cmdTokensCreate(baseURL, client, args[1:])
	case "revoke":
		return cmdTokensRevoke(baseURL, client, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "error: unknown tokens subcommand %q\n", subcmd)
		return 1
	}
}

func cmdTokensList(baseURL string, client *http.Client) int {
	resp, err := request(context.Background(), client, http.MethodGet, baseURL, "/api/tokens", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		return 1
	}
	body, err := readResp(resp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var result struct {
		Tokens []struct {
			ClientID string `json:"client_id"`
			Domain   string `json:"domain"`
			Public   bool   `json:"public"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintln(os.Stderr, string(body))
		return 1
	}

	if len(result.Tokens) == 0 {
		fmt.Println("No tokens found.")
		return 0
	}

	fmt.Printf("%-36s %-20s %s\n", "CLIENT_ID", "DOMAIN", "PUBLIC")
	fmt.Println(strings.Repeat("-", 70))
	for _, t := range result.Tokens {
		pub := "no"
		if t.Public {
			pub = "yes"
		}
		fmt.Printf("%-36s %-20s %s\n", t.ClientID, t.Domain, pub)
	}
	return 0
}

func cmdTokensCreate(baseURL string, client *http.Client, args []string) int {
	domainFlag := flag.NewFlagSet("tokens create", flag.ExitOnError)
	domain := domainFlag.String("d", "", "domain name for the token (required)")
	domainFlag.Parse(args)

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "error: -d <domain> is required")
		return 1
	}

	body, _ := json.Marshal(map[string]any{
		"domain": *domain,
		"public": true,
	})

	resp, err := request(context.Background(), client, http.MethodPost, baseURL, "/api/tokens", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		return 1
	}
	resultBody, err := readResp(resp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		OK           bool   `json:"ok"`
	}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", resultBody)
		return 1
	}

	fmt.Printf("Created token: %s\n", result.ClientID)
	fmt.Printf("Secret:        %s\n", result.ClientSecret)
	fmt.Println("\nSave this secret -- it cannot be shown again!")
	return 0
}

func cmdTokensRevoke(baseURL string, client *http.Client, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: usage: authcli -s <url> tokens revoke <client-id>")
		return 1
	}

	resp, err := request(context.Background(), client, http.MethodDelete, baseURL, "/api/tokens/"+url.PathEscape(args[0]), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		return 1
	}
	if _, err := readResp(resp); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	fmt.Printf("Revoked token: %s\n", args[0])
	return 0
}

// ---------- cookie parsing ----------

// parseCookieString parses "name=value" format back into http.Cookie slices.
func parseCookieString(s string) []*http.Cookie {
	if s == "" {
		return nil
	}
	var cookies []*http.Cookie
	parts := strings.Split(s, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  strings.TrimSpace(kv[0]),
			Value: strings.TrimSpace(kv[1]),
			Path:  "/",
		})
	}
	return cookies
}