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

// TestIDOR_Medium verifies that role is taken from server-side session, not the role cookie.
func TestIDOR_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)

	t.Run("unauthenticated request returns access denied", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "Not authenticated")
	})

	t.Run("non-admin session returns access denied", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("forged role=admin cookie is ignored without valid admin session", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie(token), roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("admin session can view any profile", func(t *testing.T) {
		token := app.mustLogin(adminUsername, adminPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("expired or invalid session returns access denied", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			app.sessionCookie("invalid-token-xyz"))
		assert.Contains(t, w.Body.String(), "Session expired")
	})
}

// TestIDOR_Hard verifies proper server-side session enforcement.
func TestIDOR_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)

	t.Run("admin can view any user profile", func(t *testing.T) {
		token := app.mustLogin(adminUsername, adminPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user can view own profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user cannot view another user's profile", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		// Gordon (ID 2) trying to access Pablo (ID 3)
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.sessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
		assert.NotContains(t, w.Body.String(), "pablo")
	})

	t.Run("forged role cookie is ignored", func(t *testing.T) {
		token := app.mustLogin(gordonUsername, gordonPassword)
		// Even with role=admin cookie, Gordon cannot view Pablo's profile
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.sessionCookie(token), roleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("no session returns access denied", func(t *testing.T) {
		w := doModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "authenticated")
	})
}
