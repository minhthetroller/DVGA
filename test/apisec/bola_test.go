package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestMemberProfile_Easy verifies no auth required and any user ID is accessible.
func TestMemberProfile_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("own profile accessible", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.Equal(t, float64(2), m["id"])
	})

	t.Run("cross-user access allowed (BOLA)", func(t *testing.T) {
		// Gordon (ID=2) should be able to access Pablo (ID=3)
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.Equal(t, float64(3), m["id"])
	})

	t.Run("sensitive fields exposed (email, phone)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/1", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "email")
	})

	t.Run("nonexistent member returns 404", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/999", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusNotFound)
	})
}

// TestMemberProfile_Medium verifies X-User-Id header can be forged.
func TestMemberProfile_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("request without X-User-Id header is forbidden", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("matching X-User-Id header grants access", func(t *testing.T) {
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/2", "",
			map[string]string{"X-User-Id": "2"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("forged X-User-Id=3 grants access to pablo (BOLA)", func(t *testing.T) {
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/3", "",
			map[string]string{"X-User-Id": "3"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.Equal(t, float64(3), m["id"])
	})
}

// TestMemberProfile_Hard verifies server-side session enforces ownership.
func TestMemberProfile_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own profile accessible", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user access blocked (gordonb cannot see pablo)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-User-Id header is ignored", func(t *testing.T) {
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/3", "",
			map[string]string{"X-User-Id": "3"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can access any user", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestOrderTracker_Easy verifies no auth required and CVV is exposed.
func TestOrderTracker_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("order accessible without ownership check", func(t *testing.T) {
		// Gordon's order is ID 1; Pablo's is ID 3
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("CVV is exposed in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "cvv")
		m := testutil.ParseJSON(t, body)
		assert.NotEmpty(t, m["cvv"])
	})
}

// TestOrderTracker_Medium verifies auth required but no ownership check; CVV still exposed.
func TestOrderTracker_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("authenticated user can access any order (BOLA)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("CVV still in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "cvv")
	})
}

// TestOrderTracker_Hard verifies ownership enforced and CVV not in response.
func TestOrderTracker_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own order accessible", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user order blocked", func(t *testing.T) {
		// Gordon tries to access Pablo's order (ID=3)
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("CVV not in response", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		body := testutil.ReadBody(t, resp)
		assert.NotContains(t, body, "cvv")
	})

	t.Run("admin can access any order", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestDocumentFetch_Easy verifies no auth required.
func TestDocumentFetch_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("any document accessible without auth", func(t *testing.T) {
		// Document 5 belongs to Pablo
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("document 1 accessible (gordon accessing admin's doc)", func(t *testing.T) {
		// Gordon can access document 1 which belongs to admin (BOLA — no ownership check in Easy)
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/1", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestDocumentFetch_Medium verifies role cookie required (client-side, forgeable).
func TestDocumentFetch_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("no role cookie returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("role=user cookie grants access", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "",
			gordonCookie, testutil.RoleCookie("user"))
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("role=user cookie allows cross-user access (BOLA)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "",
			gordonCookie, testutil.RoleCookie("user"))
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.Equal(t, float64(5), m["id"])
	})
}

// TestDocumentFetch_Hard verifies server-side session + ownership for confidential docs.
func TestDocumentFetch_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)
	adminToken := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	adminCookie := app.SessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "")
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own document accessible", func(t *testing.T) {
		// Documents 3,4 belong to Gordon (user ID=2)
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user confidential document blocked", func(t *testing.T) {
		// Document 6 belongs to user 1337 (ID=4), classified confidential
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/6", "", gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can access any document", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "", adminCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}
