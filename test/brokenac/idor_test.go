package brokenactest

import (
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

// TestIDOR_Medium verifies the intentionally client-controlled role cookie check.
func TestIDOR_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)

	t.Run("request without role cookie returns access denied", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("non-admin session without role cookie returns access denied", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("forged role=admin cookie grants cross-user access", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token), roleCookie("admin"))
		body := w.Body.String()
		assert.Contains(t, body, "admin")
		assert.Contains(t, body, "Admin API Key")
	})

	t.Run("role=admin cookie alone can view any profile", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("non-admin role cookie returns access denied", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			roleCookie("user"))
		assert.Contains(t, w.Body.String(), "Access denied")
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
