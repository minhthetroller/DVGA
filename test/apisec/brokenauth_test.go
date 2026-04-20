package apisectest

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestMobileLogin_Easy verifies alg:none JWT is returned (easily forgeable).
func TestMobileLogin_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)

	t.Run("valid credentials return a token", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.NotEmpty(t, m["token"])
	})

	t.Run("token uses alg:none (no signature)", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		token, _ := m["token"].(string)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		assert.Contains(t, string(headerJSON), `"none"`)
		assert.Empty(t, parts[2]) // no signature
	})

	t.Run("invalid credentials return 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"wrong"}`)
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestMobileLogin_Medium verifies HS256 with weak "secret" key.
func TestMobileLogin_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)

	t.Run("valid credentials return a token", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		assert.NotEmpty(t, m["token"])
	})

	t.Run("token header indicates HS256", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		token, _ := m["token"].(string)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		assert.Contains(t, string(headerJSON), "HS256")
	})
}

// TestMobileLogin_Hard verifies opaque crypto token issued.
func TestMobileLogin_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)

	t.Run("valid credentials return opaque token", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		token, _ := m["token"].(string)
		assert.NotEmpty(t, token)
		// Opaque token should not have JWT structure (3 parts)
		assert.False(t, strings.Count(token, ".") == 2)
	})

	t.Run("two logins produce different tokens", func(t *testing.T) {
		resp1 := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		resp2 := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body1 := testutil.ParseJSON(t, testutil.ReadBody(t, resp1))
		body2 := testutil.ParseJSON(t, testutil.ReadBody(t, resp2))
		assert.NotEqual(t, body1["token"], body2["token"])
	})
}

// TestSessionRenewal_Easy verifies base64(userID) refresh token — trivially forgeable.
func TestSessionRenewal_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)

	t.Run("base64-encoded user ID as refresh token works", func(t *testing.T) {
		// Forge refresh token for user ID 1
		forgedToken := base64.StdEncoding.EncodeToString([]byte("1"))
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+forgedToken+`"}`)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "access_token")
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"notbase64!!"}`)
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestSessionRenewal_Hard verifies one-time crypto/rand token, revoked after use.
func TestSessionRenewal_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)

	t.Run("invalid token returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"fakeinvalidtoken"}`)
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("token is revoked after first use — cannot be reused", func(t *testing.T) {
		// Login in hard mode — stores an opaque token in api_tokens table
		loginResp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		testutil.AssertStatus(t, loginResp, http.StatusOK)
		loginBody := testutil.ParseJSON(t, testutil.ReadBody(t, loginResp))
		token, _ := loginBody["token"].(string)
		assert.NotEmpty(t, token)

		// First refresh — must succeed
		refreshResp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+token+`"}`)
		testutil.AssertStatus(t, refreshResp, http.StatusOK)
		testutil.ReadBody(t, refreshResp) // drain

		// Second refresh with same token — must be rejected (token revoked)
		reusedResp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+token+`"}`)
		testutil.AssertStatus(t, reusedResp, http.StatusUnauthorized)
	})
}
