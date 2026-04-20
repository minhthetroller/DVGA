package cryptoctest

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDataExposure_Easy verifies notes are stored and displayed in plaintext.
func TestDataExposure_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("store a note and see it in plaintext", func(t *testing.T) {
		testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "add", "title", "TestNote", "value", "supersecretvalue"),
			cookie)
		w := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		// In easy mode the raw value is stored and shown
		assert.Contains(t, body, "supersecretvalue")
	})

	t.Run("existing seeded secrets shown in plaintext", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "sk-admin-4f8a9c2e1b")
	})
}

// TestDataExposure_Medium verifies notes added in medium mode are stored as base64.
// Seeded data was stored before any difficulty was set, so it appears as plaintext.
// Only notes added while in medium mode are base64-encoded in the response.
func TestDataExposure_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	const plainValue = "MY_MEDIUM_SECRET"

	t.Run("note added in medium mode is stored and shown as base64", func(t *testing.T) {
		testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "add", "title", "MedNote", "value", plainValue),
			cookie)
		w := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		expected := base64.StdEncoding.EncodeToString([]byte(plainValue))
		assert.Contains(t, body, expected, "added note should be stored and shown as base64")
		assert.NotContains(t, body, `"`+plainValue+`"`, "raw plaintext should not appear as a JSON string value")
	})
}

// TestDataExposure_Hard verifies AES-256-GCM encryption and decryption.
func TestDataExposure_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("add encrypted note requires password", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "add", "title", "HardNote", "value", "topsecret", "password", "mypassword"),
			cookie)
		body := w.Body.String()
		// The stored value should be ciphertext (base64), not plaintext
		assert.NotContains(t, body, "topsecret")
	})

	t.Run("missing password returns error", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "add", "title", "NoPass", "value", "secret"),
			cookie)
		assert.Contains(t, w.Body.String(), "Password required")
	})

	t.Run("decrypt with correct password reveals plaintext", func(t *testing.T) {
		// Add a note encrypted with "pass123"
		testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "add", "title", "DecryptMe", "value", "DECRYPTED_VALUE", "password", "pass123"),
			cookie)

		// Fetch the page — extract the stored ciphertext for "DecryptMe"
		wGet := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodGet, "/", nil, cookie)
		body := wGet.Body.String()

		// The response contains JSON like: "title": "DecryptMe", ... "content": "<ciphertext>"
		// Find "DecryptMe" then the "content": " after it
		const contentMarker = `"content": "`
		titlePos := strings.Index(body, `"DecryptMe"`)
		require.Greater(t, titlePos, 0, "DecryptMe note not found in response")
		contentPos := strings.Index(body[titlePos:], contentMarker)
		require.Greater(t, contentPos, 0, "content field not found after DecryptMe")
		start := titlePos + contentPos + len(contentMarker)
		end := strings.Index(body[start:], `"`)
		require.Greater(t, end, 0, "closing quote of ciphertext not found")
		ciphertext := body[start : start+end]
		assert.NotEmpty(t, ciphertext)

		// Decrypt with correct password — must reveal plaintext
		wDecrypt := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "decrypt", "secret_value", ciphertext, "password", "pass123"),
			cookie)
		assert.Contains(t, wDecrypt.Body.String(), "DECRYPTED_VALUE")

		// Wrong password must fail
		wWrong := testutil.DoModuleRequest(t, app, "data-exposure", http.MethodPost, "/",
			testutil.FormBody("action", "decrypt", "secret_value", ciphertext, "password", "wrongpass"),
			cookie)
		assert.Contains(t, wWrong.Body.String(), "Decryption failed")
	})
}
