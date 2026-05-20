package brokenactest

import (
	"bytes"
	"log/slog"
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestIDOR_Easy verifies any user profile can be fetched without authentication.
func TestIDOR_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("own profile returned", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil, cookie)
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("other user profile returned without privilege check", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil, cookie)
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("secrets exposed for any user", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil, cookie)
		body := w.Body.String()
		// Admin secrets should appear
		assert.Contains(t, body, "Admin API Key")
	})

	t.Run("nonexistent user ID returns error", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=999", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
	})
}

// TestIDOR_Medium verifies authentication is required, then authorization trusts a client-controlled role cookie.
func TestIDOR_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)

	t.Run("request without session returns not authenticated", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "Not authenticated")
	})

	t.Run("invalid session returns session expired", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie("invalid-token-xyz"), roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Session expired")
	})

	t.Run("valid user session without role cookie can view own profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token))
		body := w.Body.String()
		assert.Contains(t, body, "gordonb")
		assert.Contains(t, body, "SSH Key")
	})

	t.Run("valid user session without role cookie cannot access another profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("valid user session with role=user can view own profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token), roleCookie("user"))
		body := w.Body.String()
		assert.Contains(t, body, "gordonb")
		assert.Contains(t, body, "SSH Key")
	})

	t.Run("valid user session with role=user cannot access another profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token), roleCookie("user"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("valid user session with forged role=admin cookie grants another profile access", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token), roleCookie("admin"))
		body := w.Body.String()
		assert.Contains(t, body, "admin")
		assert.Contains(t, body, "Admin API Key")
	})

	t.Run("role=admin cookie alone is not enough without a session", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Not authenticated")
	})

	t.Run("malformed role cookie returns access denied and logs conversion error", func(t *testing.T) {
		var logBuf bytes.Buffer
		oldLogger := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
		t.Cleanup(func() {
			slog.SetDefault(oldLogger)
		})

		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token), roleCookie("superadmin"))
		assert.Contains(t, w.Body.String(), "Access denied")
		assert.Contains(t, logBuf.String(), "failed to convert role cookie value")
		assert.Contains(t, logBuf.String(), "superadmin")
	})
}

// TestIDOR_Hard verifies HMAC-signed stateless token enforcement.
func TestIDOR_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)

	t.Run("admin can view any user profile", func(t *testing.T) {
		token := app.mustLoginSigned(adminUsername, adminPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.signedSessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user can view own profile", func(t *testing.T) {
		token := app.mustLoginSigned(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.signedSessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user cannot view another user's profile", func(t *testing.T) {
		token := app.mustLoginSigned(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.signedSessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
		assert.NotContains(t, w.Body.String(), "pablo")
	})

	t.Run("tampered token is rejected", func(t *testing.T) {
		token := app.mustLoginSigned(gordonUsername, gordonPassword)
		runes := []rune(token)
		runes[0] = 'X'
		tampered := string(runes)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.signedSessionCookie(tampered))
		assert.Contains(t, w.Body.String(), "invalid or expired")
	})

	t.Run("forged role=admin cookie is ignored — HMAC token governs", func(t *testing.T) {
		token := app.mustLoginSigned(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.signedSessionCookie(token), roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("no signed_session cookie returns not authenticated", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "Not authenticated")
	})

	t.Run("old session_id cookie without signed_session is rejected", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "Not authenticated")
	})

	t.Run("admin viewing another user only gets public profile without secrets", func(t *testing.T) {
		token := app.mustLoginSigned(adminUsername, adminPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.signedSessionCookie(token))
		body := w.Body.String()
		assert.Contains(t, body, "gordonb")
		assert.NotContains(t, body, `"data"`)
	})
}
