package brokenactest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestPrivEsc_Easy verifies any user can perform admin actions without authentication.
func TestPrivEsc_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	cookie := app.SessionCookie(token)

	t.Run("team list visible on GET", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("promote action succeeds without admin role", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "promote", "target_user", "pablo"), cookie)
		assert.Contains(t, w.Body.String(), "promoted")
	})

	t.Run("demote action succeeds without admin role", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "demote", "target_user", "gordonb"), cookie)
		assert.Contains(t, w.Body.String(), "demoted")
	})
}

// TestPrivEsc_Medium verifies role cookie check (client-forgeable).
func TestPrivEsc_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("no role cookie returns access denied", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodGet, "/", nil, gordonCookie)
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("forged role=admin cookie grants access", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodGet, "/", nil,
			gordonCookie, testutil.RoleCookie("admin"))
		assert.NotContains(t, w.Body.String(), "Access denied")
	})

	t.Run("forged cookie allows promote action", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "promote", "target_user", "pablo"),
			gordonCookie, testutil.RoleCookie("admin"))
		assert.Contains(t, w.Body.String(), "promoted")
	})
}

// TestPrivEsc_Hard verifies server-side session enforcement blocks unauthorized actions.
func TestPrivEsc_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)

	t.Run("no session returns forbidden", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodGet, "/", nil)
		assert.Contains(t, w.Body.String(), "Forbidden")
	})

	t.Run("regular user session returns access denied", func(t *testing.T) {
		token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodGet, "/", nil,
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("regular user with forged role cookie still denied", func(t *testing.T) {
		token := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "promote", "target_user", "pablo"),
			app.SessionCookie(token), testutil.RoleCookie("admin"))
		assert.Contains(t, w.Body.String(), "Access denied")
	})

	t.Run("admin session can promote users", func(t *testing.T) {
		token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "promote", "target_user", "gordonb"),
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "promoted")
	})

	t.Run("admin session can demote users", func(t *testing.T) {
		token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
		w := testutil.DoModuleRequest(t, app, "privesc", http.MethodPost, "/",
			testutil.FormBody("action", "demote", "target_user", "gordonb"),
			app.SessionCookie(token))
		assert.Contains(t, w.Body.String(), "demoted")
	})
}
