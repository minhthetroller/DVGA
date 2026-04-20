package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Direct module request helpers (web modules) ---

// DoModuleRequest calls ServeHTTP directly on the named module.
// This bypasses the full HTTP server — suitable for all web (non-API) modules.
func DoModuleRequest(t *testing.T, app *TestApp, id, method, rawURL string, body io.Reader, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mod := app.BuildModule(id)
	req := httptest.NewRequest(method, rawURL, body)
	if method == http.MethodPost && body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	mod.ServeHTTP(w, req)
	return w
}

// --- HTTP server helpers (API modules) ---

// DoAPIRequest makes a request to the test HTTP server and returns the response.
func DoAPIRequest(t *testing.T, app *TestApp, method, path, jsonBody string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if jsonBody != "" {
		bodyReader = strings.NewReader(jsonBody)
	}
	req, err := http.NewRequest(method, app.Server.URL+path, bodyReader)
	require.NoError(t, err)
	if jsonBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	// Use a client that does not follow redirects (so 401 is visible, not /login)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// DoAPIRequestWithHeader is like DoAPIRequest but adds extra headers.
func DoAPIRequestWithHeader(t *testing.T, app *TestApp, method, path, jsonBody string, headers map[string]string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if jsonBody != "" {
		bodyReader = strings.NewReader(jsonBody)
	}
	req, err := http.NewRequest(method, app.Server.URL+path, bodyReader)
	require.NoError(t, err)
	if jsonBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// --- Response helpers ---

// ReadBody reads and closes the response body, returning it as a string.
func ReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	return string(b)
}

// ParseJSON unmarshals a JSON string into a map. Fails the test on parse error.
func ParseJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	err := json.Unmarshal([]byte(strings.TrimSpace(body)), &m)
	require.NoError(t, err, "ParseJSON: body was: %s", body)
	return m
}

// --- Assertion helpers ---

// AssertStatus asserts the HTTP status code equals want.
func AssertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	assert.Equal(t, want, resp.StatusCode, "unexpected HTTP status")
}

// AssertContains asserts haystack contains needle.
func AssertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	assert.Contains(t, haystack, needle)
}

// AssertNotContains asserts haystack does NOT contain needle.
func AssertNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	assert.NotContains(t, haystack, needle)
}

// --- Cookie/header helpers ---

// RoleCookie returns the legacy role cookie used by Medium difficulty checks.
func RoleCookie(role string) *http.Cookie {
	return &http.Cookie{Name: "role", Value: role}
}

// FormBody builds a URL-encoded form body from key-value pairs.
func FormBody(kvPairs ...string) io.Reader {
	if len(kvPairs)%2 != 0 {
		panic("FormBody: must receive an even number of key-value arguments")
	}
	vals := url.Values{}
	for i := 0; i < len(kvPairs); i += 2 {
		vals.Set(kvPairs[i], kvPairs[i+1])
	}
	return strings.NewReader(vals.Encode())
}

// AllDifficulties returns all three difficulty levels for table-driven tests.
func AllDifficulties() []core.Difficulty {
	return []core.Difficulty{core.Easy, core.Medium, core.Hard}
}
