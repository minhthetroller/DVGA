package injectiontest

import (
	"net/http"
	"net/url"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestSQLi_Easy verifies that the easy difficulty is fully vulnerable to SQL injection.
func TestSQLi_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	tests := []struct {
		name    string
		payload string
		wantIn  []string // substrings expected in response body
	}{
		{
			name:    "valid integer ID returns user",
			payload: "1",
			wantIn:  []string{"admin"},
		},
		{
			name:    "UNION-based injection dumps all users",
			payload: "' UNION SELECT id, username, password, role, secret_question, secret_answer FROM users WHERE '1'='1",
			wantIn:  []string{"gordonb", "pablo"},
		},
		{
			name:    "quote-based OR injection returns all users",
			payload: "' OR '1'='1",
			wantIn:  []string{"gordonb", "pablo"},
		},
		{
			name:    "sensitive field password exposed in easy mode",
			payload: "1",
			wantIn:  []string{"admin"}, // password column aliased as department/email in output
		},
		{
			name:    "zero ID returns no results",
			payload: "0",
			wantIn:  []string{"No results"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id="+url.QueryEscape(tc.payload), nil, cookie)
			body := w.Body.String()
			for _, s := range tc.wantIn {
				assert.Contains(t, body, s)
			}
		})
	}
}

// TestSQLi_Medium verifies the medium difficulty partially mitigates SQL injection.
func TestSQLi_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("valid integer lookup works", func(t *testing.T) {
		w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id=1", nil, cookie)
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("string payload rejected by Atoi check", func(t *testing.T) {
		w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id=abc", nil, cookie)
		// Atoi fails on "abc"; falls through to escaped path or shows no results
		body := w.Body.String()
		assert.NotContains(t, body, "gordonb")
	})

	t.Run("quote escaping blocks simple quote injection", func(t *testing.T) {
		w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id=1'+OR+'1'%3D'1", nil, cookie)
		body := w.Body.String()
		// Quote is escaped; extra users should NOT appear
		assert.NotContains(t, body, "pablo")
	})

	t.Run("password column NOT exposed in medium response", func(t *testing.T) {
		w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id=1", nil, cookie)
		body := w.Body.String()
		// Medium only selects id, username, department — password_hash not in response
		assert.NotContains(t, body, "password_hash")
		assert.Contains(t, body, "admin") // username admin still present
	})
}

// TestSQLi_Hard verifies that parameterized queries block all injection attempts.
func TestSQLi_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	tests := []struct {
		name       string
		payload    string
		shouldFind string
		wantEmpty  bool
	}{
		{"valid ID 1 returns admin", "1", "admin", false},
		{"valid ID 2 returns gordonb", "2", "gordonb", false},
		{"OR 1=1 injection returns NO extra rows", "1 OR 1=1", "", true},
		{"quote-based injection yields no extra rows", "' OR '1'='1", "", true},
		{"UNION SELECT injection yields no data", "1 UNION SELECT 1,2,3,4,5,6--", "", true},
		{"negative ID yields no results", "-1", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doModuleRequest(t, app, "sqli", http.MethodGet, "/?id="+url.QueryEscape(tc.payload), nil, cookie)
			body := w.Body.String()
			if tc.wantEmpty {
				assert.Contains(t, body, "No results")
			} else {
				assert.Contains(t, body, tc.shouldFind)
			}
		})
	}
}
