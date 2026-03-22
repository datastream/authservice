package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Client is a thin wrapper around the authservice HTTP API.
// It can be used by third‑party applications to authenticate users,
// obtain OAuth tokens, query user info, manage client tokens, and
// interact with the OpenFGA integration.
type Client struct {
	// BaseURL of the running authservice (e.g. "http://localhost:8080").
	BaseURL    string
	HTTPClient *http.Client
	// bearer token for OAuth protected endpoints (optional).
	BearerToken string
	// session cookie for UI endpoints (optional).
	SessionCookie *http.Cookie
}

// New creates a Client with sensible defaults.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBearerToken stores a token to be sent as "Authorization: Bearer <token>".
func (c *Client) SetBearerToken(tok string) {
	c.BearerToken = tok
}

// SetSessionCookie stores a cookie (e.g. after a login POST) for UI routes.
func (c *Client) SetSessionCookie(cookie *http.Cookie) {
	c.SessionCookie = cookie
}

// do performs an HTTP request, injecting auth headers/cookies as needed.
func (c *Client) do(ctx context.Context, method, relPath string, body interface{}, query url.Values) (*http.Response, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, relPath)
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
		reqBody = &buf
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	if c.SessionCookie != nil {
		req.AddCookie(c.SessionCookie)
	}
	return c.HTTPClient.Do(req)
}

// ---------- OAuth2 helpers ----------

// TokenResponse mirrors the JSON payload returned by /oauth/token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// ClientCredentials obtains a token using the client credentials grant.
func (c *Client) ClientCredentials(ctx context.Context, clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	// The token endpoint expects application/x-www-form-urlencoded.
	resp, err := c.do(ctx, http.MethodPost, "/oauth/token", data, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed: %s", resp.Status)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	c.SetBearerToken(tr.AccessToken)
	return &tr, nil
}

// PasswordGrant obtains a token using the resource‑owner password credentials flow.
func (c *Client) PasswordGrant(ctx context.Context, clientID, clientSecret, username, password string, scopes []string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	resp, err := c.do(ctx, http.MethodPost, "/oauth/token", data, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("password grant failed: %s", resp.Status)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	c.SetBearerToken(tr.AccessToken)
	return &tr, nil
}

// UserInfo returns the user profile for the current bearer token.
type UserInfo struct {
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Login   string `json:"login"`
	Client  string `json:"client"`
	Email   string `json:"email"`
	Expires string `json:"expires"`
}

func (c *Client) UserInfo(ctx context.Context) (*UserInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, "/userinfo", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}
	var ui UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return nil, err
	}
	return &ui, nil
}

// ---------- Token (client) management ----------

type TokenForm struct {
	Domain   string `json:"domain"`
	Public   bool   `json:"public"`
	Describe string `json:"describe,omitempty"`
	UserID   string `json:"userID,omitempty"`
}

type CreateTokenResponse struct {
	Message      string `json:"message"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// CreateClientToken creates an OAuth client token for the logged‑in user.
func (c *Client) CreateClientToken(ctx context.Context, form TokenForm) (*CreateTokenResponse, error) {
	// Requires a session cookie – the caller must have logged in via /login first.
	resp, err := c.do(ctx, http.MethodPost, "/tokens", form, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create token failed: %s", resp.Status)
	}
	var out CreateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListClientTokens returns all tokens belonging to the logged‑in user.
func (c *Client) ListClientTokens(ctx context.Context) ([]TokenForm, error) {
	// The /tokens endpoint returns a JSON object with a "tokens" field.
	resp, err := c.do(ctx, http.MethodGet, "/tokens", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list tokens failed: %s", resp.Status)
	}
	var wrapper struct {
		Tokens []TokenForm `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}
	return wrapper.Tokens, nil
}

// ---------- OpenFGA SDK ----------

type FGAModel struct {
	AuthorizationModelId string `json:"authorizationModelId"`
	// The raw response from OpenFGA is returned; callers can unmarshal further if needed.
	Raw json.RawMessage `json:"-"`
}

// CreateModel creates a new OpenFGA authorization model.
func (c *Client) CreateFgaModel(ctx context.Context, modelDef interface{}) (*FGAModel, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/fga/models", modelDef, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fga create model failed: %s", resp.Status)
	}
	var out struct {
		AuthorizationModelId string `json:"authorizationModelId"`
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &FGAModel{AuthorizationModelId: out.AuthorizationModelId, Raw: data}, nil
}

// GetModel fetches an existing model by its ID.
func (c *Client) GetFgaModel(ctx context.Context, modelID string) (*FGAModel, error) {
	resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/fga/models/%s", modelID), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fga get model failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out struct {
		AuthorizationModelId string `json:"authorizationModelId"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &FGAModel{AuthorizationModelId: out.AuthorizationModelId, Raw: data}, nil
}

// EvaluatePermission runs a check request against a specific model.
type CheckRequest struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type CheckResponse struct {
	Allowed bool `json:"allowed"`
	// raw may contain additional fields like "requestId".
	Raw json.RawMessage `json:"-"`
}

func (c *Client) EvaluateFgaPermission(ctx context.Context, modelID string, req CheckRequest) (*CheckResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/fga/models/%s/evaluate", modelID), req, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fga evaluate failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &CheckResponse{Allowed: out.Allowed, Raw: data}, nil
}

// WriteTuples creates or updates tuples for a given model.
func (c *Client) WriteFgaTuples(ctx context.Context, modelID string, body interface{}) error {
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/fga/models/%s/tuples", modelID), body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fga write tuples failed: %s", resp.Status)
	}
	return nil
}

// DeleteFgaTuples removes tuples for a given model.
func (c *Client) DeleteFgaTuples(ctx context.Context, modelID string, body interface{}) error {
	resp, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/fga/models/%s/tuples", modelID), body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fga delete tuples failed: %s", resp.Status)
	}
	return nil
}

// ---------- Helper for session login (optional) ----------
// Login performs a form post to /login and stores the returned session cookie.
func (c *Client) Login(ctx context.Context, username, password string) error {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	resp, err := c.do(ctx, http.MethodPost, "/login", data, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: %s", resp.Status)
	}
	// Extract session cookie (named whatever the server uses – default is "session_id").
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, "session") { // generic match
			c.SetSessionCookie(ck)
			break
		}
	}
	return nil
}
