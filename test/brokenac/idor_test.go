package brokenactest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestIDOR_Easy verifies any user profile can be fetched without authentication.
func TestIDOR_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("own profile returned", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil, cookie)
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("other user profile returned without privilege check", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil, cookie)
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("secrets exposed for any user", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil, cookie)
		body := w.Body.String()
		// Admin secrets should appear
		assert.Contains(t, body, "Admin API Key")
	})

	t.Run("nonexistent user ID returns error", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=999", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
	})
}

// TestIDOR_Medium verifies the role cookie check (client-forgeable) is used.
func TestIDOR_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	sessionCookie := app.SessionCookie(token)

	t.Run("no role cookie returns access denied", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil, sessionCookie)
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("forged role=admin cookie grants access to any profile", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil,
			sessionCookie, testutil.RoleCookie("admin"))
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("forged role=admin allows cross-user fetch", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			sessionCookie, testutil.RoleCookie("admin"))
		assert.Contains(t, w.Body.String(), "pablo")
	})
}

// TestIDOR_Hard verifies proper server-side session enforcement.
func TestIDOR_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)

	t.Run("admin can view any user profile", func(t *testing.T) {
		token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user can view own profile", func(t *testing.T) {
		token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=2", nil,
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "gordonb")
	})

	t.Run("regular user cannot view another user's profile", func(t *testing.T) {
		token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
		// Gordon (ID 2) trying to access Pablo (ID 3)
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
		assert.NotContains(t, w.Body.String(), "pablo")
	})

	t.Run("forged role cookie is ignored", func(t *testing.T) {
		token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
		// Even with role=admin cookie, Gordon cannot view Pablo's profile
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=3", nil,
			app.SessionCookie(token), testutil.RoleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("no session returns access denied", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "idor", http.MethodGet, "/?user_id=1", nil)
		assert.Contains(t, w.Body.String(), "authenticated")
	})
}
