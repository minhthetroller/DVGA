package misconfigtest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestSecurityHeaders_Easy verifies permissive CORS (*) and no security headers.
func TestSecurityHeaders_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)

	t.Run("CORS set to wildcard", func(t *testing.T) {
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("no X-Frame-Options header", func(t *testing.T) {
		assert.Empty(t, w.Header().Get("X-Frame-Options"))
	})

	t.Run("no CSP header", func(t *testing.T) {
		assert.Empty(t, w.Header().Get("Content-Security-Policy"))
	})

	t.Run("no HSTS header", func(t *testing.T) {
		assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
	})

	t.Run("body audit shows permissive CORS", func(t *testing.T) {
		assert.Contains(t, w.Body.String(), "permissive")
	})
}

// TestSecurityHeaders_Medium verifies X-Content-Type-Options present, CORS weak (reflects similar origin).
func TestSecurityHeaders_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("X-Content-Type-Options set to nosniff", func(t *testing.T) {
		w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})

	t.Run("no wildcard CORS by default", func(t *testing.T) {
		w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)
		assert.NotEqual(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("no X-Frame-Options", func(t *testing.T) {
		w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)
		assert.Empty(t, w.Header().Get("X-Frame-Options"))
	})

	t.Run("no CSP", func(t *testing.T) {
		w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)
		assert.Empty(t, w.Header().Get("Content-Security-Policy"))
	})
}

// TestSecurityHeaders_Hard verifies all security headers are present with strict values.
func TestSecurityHeaders_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	w := doModuleRequest(t, app, "security-headers", http.MethodGet, "/", nil, cookie)

	t.Run("X-Frame-Options is DENY", func(t *testing.T) {
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	})

	t.Run("X-Content-Type-Options is nosniff", func(t *testing.T) {
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})

	t.Run("CSP default-src self", func(t *testing.T) {
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
	})

	t.Run("HSTS header present", func(t *testing.T) {
		assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	})

	t.Run("Referrer-Policy is no-referrer", func(t *testing.T) {
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	})

	t.Run("no wildcard CORS", func(t *testing.T) {
		assert.NotEqual(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})
}
