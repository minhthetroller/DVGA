package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestUserStatusToggle_Easy verifies anyone can suspend a user without auth.
func TestUserStatusToggle_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("regular user can suspend another user", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "toggled")
	})
}

// TestUserStatusToggle_Medium verifies X-Role header check is bypassable.
func TestUserStatusToggle_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("request without X-Role header is forbidden", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-Role:admin header grants access", func(t *testing.T) {
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/members/3/suspend", "",
			map[string]string{"X-Role": "admin"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "toggled")
	})
}

// TestUserStatusToggle_Hard verifies server-side session role enforced.
func TestUserStatusToggle_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("regular user session forbidden", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-Role header is ignored", func(t *testing.T) {
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/members/3/suspend", "",
			map[string]string{"X-Role": "admin"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin session can suspend", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestSupportTools_Easy verifies any authenticated user can access admin dashboard.
func TestSupportTools_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("regular user can access admin dashboard", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "users")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestSupportTools_Medium verifies role cookie required (bypassable).
func TestSupportTools_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("no role cookie forbidden", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged role=admin cookie grants access", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "",
			gordonCookie, testutil.RoleCookie("admin"))
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestSupportTools_Hard verifies only admin/support/helpdesk session roles allowed.
func TestSupportTools_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)
	helpdeskToken := app.MustLogin(testutil.HelpdeskUsername, testutil.HelpdeskPassword)
	helpdeskCookie := app.SessionCookie(helpdeskToken)

	t.Run("regular user denied", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged role cookie ignored", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "",
			gordonCookie, testutil.RoleCookie("admin"))
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin session allowed", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("helpdesk session allowed", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", helpdeskCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestRefundProcessor_Easy verifies any authenticated user can process refunds.
func TestRefundProcessor_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("regular user can refund any order", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/2/refund", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "refund processed")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestRefundProcessor_Medium verifies helpdesk/admin role required, no assignment check.
func TestRefundProcessor_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	helpdeskToken := app.MustLogin(testutil.HelpdeskUsername, testutil.HelpdeskPassword)
	helpdeskCookie := app.SessionCookie(helpdeskToken)

	t.Run("regular user forbidden", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("helpdesk can refund unassigned order (no check)", func(t *testing.T) {
		// Order 4 is assigned to Pablo, not helpdesk — but Medium has no assignment check
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", helpdeskCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestRefundProcessor_Hard verifies helpdesk can only refund assigned orders.
func TestRefundProcessor_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	helpdeskToken := app.MustLogin(testutil.HelpdeskUsername, testutil.HelpdeskPassword)
	helpdeskCookie := app.SessionCookie(helpdeskToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)

	t.Run("helpdesk can refund assigned order (ID=1)", func(t *testing.T) {
		// Seed: order 1 assigned_to=5 (helpdesk)
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "", helpdeskCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("helpdesk cannot refund unassigned order (ID=4)", func(t *testing.T) {
		// Order 4 (pablo's) not assigned to helpdesk
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", helpdeskCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can refund any order", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}
