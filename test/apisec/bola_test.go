package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestMemberProfile_Easy verifies no auth required and any user ID is accessible.
func TestMemberProfile_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("own profile accessible", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.Equal(t, float64(2), m["id"])
	})

	t.Run("cross-user access allowed (BOLA)", func(t *testing.T) {
		// Gordon (ID=2) should be able to access Pablo (ID=3)
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.Equal(t, float64(3), m["id"])
	})

	t.Run("sensitive fields exposed (email, phone)", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/1", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "email")
	})

	t.Run("nonexistent member returns 404", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/999", "", gordonCookie)
		assertStatus(t, resp, http.StatusNotFound)
	})
}

// TestMemberProfile_Medium verifies X-User-Id header can be forged.
func TestMemberProfile_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("request without X-User-Id header is forbidden", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("matching X-User-Id header grants access", func(t *testing.T) {
		resp := doAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/2", "",
			map[string]string{"X-User-Id": "2"}, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("forged X-User-Id=3 grants access to pablo (BOLA)", func(t *testing.T) {
		resp := doAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/3", "",
			map[string]string{"X-User-Id": "3"}, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.Equal(t, float64(3), m["id"])
	})
}

// TestMemberProfile_Hard verifies server-side session enforces ownership.
func TestMemberProfile_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own profile accessible", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user access blocked (gordonb cannot see pablo)", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("forged X-User-Id header is ignored", func(t *testing.T) {
		resp := doAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/members/3", "",
			map[string]string{"X-User-Id": "3"}, gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can access any user", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/members/2", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestOrderTracker_Easy verifies no auth required and CVV is exposed.
func TestOrderTracker_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("order accessible without ownership check", func(t *testing.T) {
		// Gordon's order is ID 1; Pablo's is ID 3
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("CVV is exposed in response", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "cvv")
		m := parseJSON(t, body)
		assert.NotEmpty(t, m["cvv"])
	})
}

// TestOrderTracker_Medium verifies auth required but no ownership check; CVV still exposed.
func TestOrderTracker_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("authenticated user can access any order (BOLA)", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("CVV still in response", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		body := readBody(t, resp)
		assert.Contains(t, body, "cvv")
	})
}

// TestOrderTracker_Hard verifies ownership enforced and CVV not in response.
func TestOrderTracker_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own order accessible", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user order blocked", func(t *testing.T) {
		// Gordon tries to access Pablo's order (ID=3)
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("CVV not in response", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/1", "", gordonCookie)
		body := readBody(t, resp)
		assert.NotContains(t, body, "cvv")
	})

	t.Run("admin can access any order", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/orders/3", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestDocumentFetch_Easy verifies no auth required.
func TestDocumentFetch_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("any document accessible without auth", func(t *testing.T) {
		// Document 5 belongs to Pablo
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("document 1 accessible (gordon accessing admin's doc)", func(t *testing.T) {
		// Gordon can access document 1 which belongs to admin (BOLA — no ownership check in Easy)
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/1", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestDocumentFetch_Medium verifies role cookie required (client-side, forgeable).
func TestDocumentFetch_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("no role cookie returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("role=user cookie grants access", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "",
			gordonCookie, roleCookie("user"))
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("role=user cookie allows cross-user access (BOLA)", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "",
			gordonCookie, roleCookie("user"))
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.Equal(t, float64(5), m["id"])
	})
}

// TestDocumentFetch_Hard verifies server-side session + ownership for confidential docs.
func TestDocumentFetch_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)
	adminToken := app.mustLogin(adminUsername, adminPassword)
	adminCookie := app.sessionCookie(adminToken)

	t.Run("no session returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("own document accessible", func(t *testing.T) {
		// Documents 3,4 belong to Gordon (user ID=2)
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/3", "", gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("cross-user confidential document blocked", func(t *testing.T) {
		// Document 6 belongs to user 1337 (ID=4), classified confidential
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/6", "", gordonCookie)
		assertStatus(t, resp, http.StatusForbidden)
	})

	t.Run("admin can access any document", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/documents/5", "", adminCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}
