package cryptoctest

import (
	"fmt"
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestWeakPasswd_Easy verifies plaintext passwords are exposed in the response.
func TestWeakPasswd_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	w := testutil.DoModuleRequest(t, app, "weak-passwd", http.MethodGet, "/", nil, cookie)
	body := w.Body.String()

	t.Run("password field present in response", func(t *testing.T) {
		assert.Contains(t, body, `"password"`)
	})

	t.Run("plaintext password values visible", func(t *testing.T) {
		// Seed passwords are known: admin/abc123/letmein/charley
		assert.Contains(t, body, "abc123")
		assert.Contains(t, body, "letmein")
	})
}

// TestWeakPasswd_Medium verifies MD5 hashes are returned instead of plaintext.
func TestWeakPasswd_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	w := testutil.DoModuleRequest(t, app, "weak-passwd", http.MethodGet, "/", nil, cookie)
	body := w.Body.String()

	t.Run("password_hash field present", func(t *testing.T) {
		assert.Contains(t, body, `"password_hash"`)
	})

	t.Run("plaintext passwords not in response", func(t *testing.T) {
		assert.NotContains(t, body, "abc123")
		assert.NotContains(t, body, "letmein")
	})

	t.Run("MD5 hash of known password is present", func(t *testing.T) {
		// MD5("admin") = 21232f297a57a5a743894a0e4a801fc3
		assert.Contains(t, body, "21232f297a57a5a743894a0e4a801fc3")
	})

	t.Run("hash is 32 hex chars (MD5 length)", func(t *testing.T) {
		// abc123 MD5 = e99a18c428cb38d5f260853678922e03
		assert.Contains(t, body, "e99a18c428cb38d5f260853678922e03")
	})
}

// TestWeakPasswd_Hard verifies no password data is exposed and bcrypt verify works.
func TestWeakPasswd_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("user listing contains no password field", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "weak-passwd", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		// JSON output should not contain password fields (only id, username, role)
		// The HTML form itself contains type="password" but the JSON response should not
		assert.NotContains(t, body, `"password_hash"`)
		assert.NotContains(t, body, "abc123")
		// Verify the JSON lacks a "password" key (the HTML form has type="password" so we
		// check for the JSON key format specifically)
		assert.NotContains(t, body, `"password":`)
	})

	t.Run("verify correct password returns verified true", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "weak-passwd", http.MethodPost, "/",
			testutil.FormBody("action", "verify", "username", "gordonb", "guess", "abc123"),
			cookie)
		body := w.Body.String()
		assert.Contains(t, body, fmt.Sprintf("%v", true))
	})

	t.Run("verify wrong password returns verified false", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "weak-passwd", http.MethodPost, "/",
			testutil.FormBody("action", "verify", "username", "gordonb", "guess", "wrongpassword"),
			cookie)
		body := w.Body.String()
		assert.Contains(t, body, fmt.Sprintf("%v", false))
	})
}
