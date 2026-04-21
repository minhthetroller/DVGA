package apisectest

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestMobileLogin_Easy verifies alg:none JWT is returned (easily forgeable).
func TestMobileLogin_Easy(t *testing.T) {
	app := newTestApp(t)

	t.Run("valid credentials return a token", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.NotEmpty(t, m["token"])
	})

	t.Run("token uses alg:none (no signature)", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		token, _ := m["token"].(string)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		assert.Contains(t, string(headerJSON), `"none"`)
		assert.Empty(t, parts[2]) // no signature
	})

	t.Run("invalid credentials return 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"wrong"}`)
		assertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestMobileLogin_Medium verifies HS256 with weak "secret" key.
func TestMobileLogin_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)

	t.Run("valid credentials return a token", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		assert.NotEmpty(t, m["token"])
	})

	t.Run("token header indicates HS256", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		token, _ := m["token"].(string)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		assert.Contains(t, string(headerJSON), "HS256")
	})
}

// TestMobileLogin_Hard verifies opaque crypto token issued.
func TestMobileLogin_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)

	t.Run("valid credentials return opaque token", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		token, _ := m["token"].(string)
		assert.NotEmpty(t, token)
		// Opaque token should not have JWT structure (3 parts)
		assert.False(t, strings.Count(token, ".") == 2)
	})

	t.Run("two logins produce different tokens", func(t *testing.T) {
		resp1 := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		resp2 := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		body1 := parseJSON(t, readBody(t, resp1))
		body2 := parseJSON(t, readBody(t, resp2))
		assert.NotEqual(t, body1["token"], body2["token"])
	})
}

// TestSessionRenewal_Easy verifies base64(userID) refresh token — trivially forgeable.
func TestSessionRenewal_Easy(t *testing.T) {
	app := newTestApp(t)

	t.Run("base64-encoded user ID as refresh token works", func(t *testing.T) {
		// Forge refresh token for user ID 1
		forgedToken := base64.StdEncoding.EncodeToString([]byte("1"))
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+forgedToken+`"}`)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		assert.Contains(t, body, "access_token")
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"notbase64!!"}`)
		assertStatus(t, resp, http.StatusUnauthorized)
	})
}

// TestSessionRenewal_Hard verifies one-time crypto/rand token, revoked after use.
func TestSessionRenewal_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)

	t.Run("invalid token returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"fakeinvalidtoken"}`)
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("token is revoked after first use — cannot be reused", func(t *testing.T) {
		// Login in hard mode — stores an opaque token in api_tokens table
		loginResp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/token",
			`{"username":"gordonb","password":"abc123"}`)
		assertStatus(t, loginResp, http.StatusOK)
		loginBody := parseJSON(t, readBody(t, loginResp))
		token, _ := loginBody["token"].(string)
		assert.NotEmpty(t, token)

		// First refresh — must succeed
		refreshResp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+token+`"}`)
		assertStatus(t, refreshResp, http.StatusOK)
		readBody(t, refreshResp) // drain

		// Second refresh with same token — must be rejected (token revoked)
		reusedResp := doAPIRequest(t, app, http.MethodPost, "/api/v1/auth/refresh",
			`{"refresh_token":"`+token+`"}`)
		assertStatus(t, reusedResp, http.StatusUnauthorized)
	})
}
