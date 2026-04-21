package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestUserStatusToggle_Easy verifies anyone can suspend a user without auth.
func TestUserStatusToggle_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("regular user can suspend another user", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "toggled")
	})
}

// TestUserStatusToggle_Medium verifies X-Role header check is bypassable.
func TestUserStatusToggle_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("request without X-Role header is forbidden", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-Role:admin header grants access", func(t *testing.T) {
		resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/members/3/suspend", "",
			map[string]string{"X-Role": "admin"}, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "toggled")
	})
}

// TestUserStatusToggle_Hard verifies server-side session role enforced.
func TestUserStatusToggle_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("regular user session forbidden", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-Role header is ignored", func(t *testing.T) {
		resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/members/3/suspend", "",
			map[string]string{"X-Role": "admin"}, gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin session can suspend", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/3/suspend", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestSupportTools_Easy verifies any authenticated user can access admin dashboard.
func TestSupportTools_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("regular user can access admin dashboard", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "users")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestSupportTools_Medium verifies role cookie required (bypassable).
func TestSupportTools_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("no role cookie forbidden", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged role=admin cookie grants access", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "",
			gordonCookie, roleCookie("admin"))
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestSupportTools_Hard verifies only admin/support/helpdesk session roles allowed.
func TestSupportTools_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)
	helpdeskToken := app.mustLogin(helpdeskUsername, helpdeskPassword)
	helpdeskCookie := app.sessionCookie(helpdeskToken)

	t.Run("regular user denied", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged role cookie ignored", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "",
			gordonCookie, roleCookie("admin"))
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin session allowed", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("helpdesk session allowed", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/admin/dashboard", "", helpdeskCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestRefundProcessor_Easy verifies any authenticated user can process refunds.
func TestRefundProcessor_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("regular user can refund any order", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/2/refund", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "refund processed")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestRefundProcessor_Medium verifies helpdesk/admin role required, no assignment check.
func TestRefundProcessor_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	helpdeskToken := app.mustLogin(helpdeskUsername, helpdeskPassword)
	helpdeskCookie := app.sessionCookie(helpdeskToken)

	t.Run("regular user forbidden", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("helpdesk can refund unassigned order (no check)", func(t *testing.T) {
		// Order 4 is assigned to Pablo, not helpdesk — but Medium has no assignment check
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", helpdeskCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestRefundProcessor_Hard verifies helpdesk can only refund assigned orders.
func TestRefundProcessor_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	helpdeskToken := app.mustLogin(helpdeskUsername, helpdeskPassword)
	helpdeskCookie := app.sessionCookie(helpdeskToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)

	t.Run("helpdesk can refund assigned order (ID=1)", func(t *testing.T) {
		// Seed: order 1 assigned_to=5 (helpdesk)
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/refund", "", helpdeskCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("helpdesk cannot refund unassigned order (ID=4)", func(t *testing.T) {
		// Order 4 (pablo's) not assigned to helpdesk
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", helpdeskCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can refund any order", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/4/refund", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}
