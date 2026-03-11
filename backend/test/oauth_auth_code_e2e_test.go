package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	serverAddr      = "http://localhost:8080"
	clientID        = "test-client"
	clientSecret    = "test-client-secret"
	redirectURI     = "http://localhost:9999/callback"
	sessionCookie   = "sso_session_token"
	signingKey      = "test-signing-key"
	accessTokenExp  = "3600"
	refreshTokenExp = "86400"
	sessionExp      = "3600"
)

func TestOAuthAuthorizationCodeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	pgURL := testPostgresURL()
	pool := connectTestDB(ctx, t, pgURL)
	defer pool.Close()

	cleanup := func() {
		if err := resetDB(ctx, pool); err != nil {
			t.Logf("db cleanup failed: %v", err)
		}
	}
	defer cleanup()

	cmd, logs := startServer(ctx, t, pgURL)
	defer stopServer(t, cmd, logs)

	if err := waitForHTTP(ctx, serverAddr+"/.well-known/jwks.json"); err != nil {
		cleanup()
		t.Fatalf("server did not become ready: %v", err)
	}

	if err := resetDB(ctx, pool); err != nil {
		cleanup()
		t.Fatalf("db reset failed: %v", err)
	}

	if err := insertTestClient(ctx, pool); err != nil {
		cleanup()
		t.Fatalf("failed to insert test client: %v", err)
	}

	registerUser(t, "test.user@example.com", "Test User", "Passw0rd!")
	sessionToken := loginUser(t, "test.user@example.com", "Passw0rd!")

	code := getAuthorizationCode(t, sessionToken)
	accessToken := exchangeCodeForToken(t, code)
	userinfo := getUserInfo(t, accessToken)

	if userinfo["email"] != "test.user@example.com" {
		t.Fatalf("unexpected userinfo email: %v", userinfo["email"])
	}
	if userinfo["name"] != "Test User" {
		t.Fatalf("unexpected userinfo name: %v", userinfo["name"])
	}
	if userinfo["sub"] == "" {
		t.Fatalf("unexpected userinfo subject: %v", userinfo["sub"])
	}
}

func testPostgresURL() string {
	if v := os.Getenv("TEST_POSTGRES_URL"); v != "" {
		return v
	}
	return "postgres://sso_test:sso_test@localhost:5433/sso_test?sslmode=disable"
}

func connectTestDB(ctx context.Context, t *testing.T, dsn string) *pgxpool.Pool {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect to test db: %v", err)
	}

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()

	var lastErr error
	for {
		if err := pool.Ping(ctx); err == nil {
			return pool
		} else {
			lastErr = err
		}
		select {
		case <-deadline.C:
			t.Fatalf("test db is not reachable: %v", lastErr)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func resetDB(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, "TRUNCATE TABLE credentials, identities, users, clients RESTART IDENTITY CASCADE")
	return err
}

func insertTestClient(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx,
		"INSERT INTO clients (name, client_id, redirect_uris, client_secret, scopes, status) VALUES ($1, $2, $3, $4, $5, $6)",
		"E2E Test Client",
		clientID,
		[]string{redirectURI},
		clientSecret,
		[]string{"profile", "email"},
		"active",
	)
	return err
}

func startServer(ctx context.Context, t *testing.T, pgURL string) (*exec.Cmd, *bytes.Buffer) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	backendDir := filepath.Dir(wd)
	logsDir := filepath.Join(backendDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}

	cmd := exec.CommandContext(ctx, "go", "run", ".")
	cmd.Dir = backendDir
	cmd.Env = append(os.Environ(),
		"POSTGRES_URL="+pgURL,
		"MIGRATIONS_PATH=migrations",
		"SIGNING_KEY="+signingKey,
		"ACCESS_TOKEN_EXPIRATION="+accessTokenExp,
		"REFRESH_TOKEN_EXPIRATION="+refreshTokenExp,
		"SESSION_EXPIRATION="+sessionExp,
	)

	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	return cmd, buf
}

func stopServer(t *testing.T, cmd *exec.Cmd, logs *bytes.Buffer) {
	if cmd.Process == nil {
		return
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if logs != nil && logs.Len() > 0 {
		t.Logf("server logs:\n%s", logs.String())
	}
}

func waitForHTTP(ctx context.Context, endpoint string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		select {
		case <-deadline.C:
			if err == nil {
				err = fmt.Errorf("unexpected status: %v", respStatus(resp))
			}
			return err
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func respStatus(resp *http.Response) string {
	if resp == nil {
		return "no response"
	}
	return resp.Status
}

func registerUser(t *testing.T, email, name, password string) {
	payload := map[string]string{
		"email":    email,
		"name":     name,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, serverAddr+"/auth/register?provider=email", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build register request: %v", err)
	}
	addJSONHeaders(req)

	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		failWithBody(t, resp, "register")
	}
}

func loginUser(t *testing.T, email, password string) string {
	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, serverAddr+"/auth/login?provider=email", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build login request: %v", err)
	}
	addJSONHeaders(req)

	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		failWithBody(t, resp, "login")
	}

	cookie := findCookie(resp.Cookies(), sessionCookie)
	if cookie == "" {
		failWithBody(t, resp, "login (missing session cookie)")
	}

	return cookie
}

func getAuthorizationCode(t *testing.T, sessionToken string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", "state-123")
	q.Set("scope", "profile email")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, serverAddr+"/oauth2/auth?"+q.Encode(), nil)
	if err != nil {
		t.Fatalf("failed to build authorize request: %v", err)
	}
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", sessionCookie, sessionToken))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		failWithBody(t, resp, "authorize")
	}

	location := resp.Header.Get("Location")
	if location == "" {
		failWithBody(t, resp, "authorize (missing Location)")
	}

	redir, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}

	code := redir.Query().Get("code")
	state := redir.Query().Get("state")
	if code == "" {
		t.Fatalf("missing authorization code in redirect: %v", location)
	}
	if state != "state-123" {
		t.Fatalf("unexpected state in redirect: %v", state)
	}

	return code
}

func exchangeCodeForToken(t *testing.T, code string) string {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest(http.MethodPost, serverAddr+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to build token request: %v", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		failWithBody(t, resp, "token")
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("missing access_token in response: %v", payload)
	}

	return accessToken
}

func getUserInfo(t *testing.T, accessToken string) map[string]any {
	req, err := http.NewRequest(http.MethodGet, serverAddr+"/oauth2/userinfo", nil)
	if err != nil {
		t.Fatalf("failed to build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		failWithBody(t, resp, "userinfo")
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}

	return payload
}

func addJSONHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
}

func doRequest(t *testing.T, req *http.Request) *http.Response {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func failWithBody(t *testing.T, resp *http.Response, label string) {
	body, _ := io.ReadAll(resp.Body)
	t.Fatalf("%s failed: status=%d body=%s", label, resp.StatusCode, string(body))
}

func findCookie(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
