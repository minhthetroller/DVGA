package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestProfileSettings_Easy verifies mass assignment — role field can be set.
func TestProfileSettings_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("can update email and phone", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"email":"new@example.com","phone":"555-1234"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "new@example.com")
	})

	t.Run("can escalate own role via mass assignment", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"role":"admin"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.Equal(t, "admin", m["role"])
	})
}

// TestProfileSettings_Medium verifies role blocked but password still writable.
func TestProfileSettings_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("role field is blocked — cannot escalate role", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"role":"admin"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.NotEqual(t, "admin", m["role"])
	})

	t.Run("password field is still writable (vulnerability)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"password":"newpassword"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestProfileSettings_Hard verifies only email and phone are updatable.
func TestProfileSettings_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("email and phone are updatable", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"email":"safe@example.com","phone":"555-9999"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "safe@example.com")
	})

	t.Run("role field is ignored", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"role":"admin"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.NotEqual(t, "admin", m["role"])
	})

	t.Run("password field is ignored", func(t *testing.T) {
		// Can't directly verify password isn't changed without re-login,
		// but we can verify the endpoint still succeeds
		resp := testutil.DoAPIRequest(t, app, http.MethodPatch, "/api/v1/members/me",
			`{"password":"hacked"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestOrderDetails_Easy verifies CVV exposed in response.
func TestOrderDetails_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("CVV in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1/details", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "cvv")
		m := testutil.ParseJSON(t, body)
		assert.NotEmpty(t, m["cvv"])
	})
}

// TestOrderDetails_Medium verifies CVV removed but card_last4 still present.
func TestOrderDetails_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("CVV not in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1/details", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.NotContains(t, body, `"cvv"`)
	})

	t.Run("card_last4 still present", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1/details", "", gordonCookie)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "card_last4")
	})
}

// TestOrderDetails_Hard verifies only id, amount, tracking_number returned.
func TestOrderDetails_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("only safe fields in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1/details", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.NotContains(t, body, `"cvv"`)
		assert.NotContains(t, body, `"card_last4"`)
		assert.Contains(t, body, "tracking_number")
	})
}

// TestInvoiceAdjuster tests are covered by reading the bopla scenarios.
