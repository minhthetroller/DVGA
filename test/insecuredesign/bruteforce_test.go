package insecuredesigntest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestBruteForce_Easy verifies no rate limiting — unlimited login attempts allowed.
func TestBruteForce_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("correct credentials succeed", func(t *testing.T) {
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("wrong credentials return invalid message", func(t *testing.T) {
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "gordonb", "password", "wrong"), cookie)
		assert.Contains(t, w.Body.String(), `"success":false`)
	})

	t.Run("20 consecutive failed attempts allowed — no lockout", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				formBody("username", "pablo", "password", "wrong"), cookie)
		}
		// After 20 failed attempts, correct password still works
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "pablo", "password", "letmein"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})
}

// TestBruteForce_Medium verifies lockout after 10 failed attempts (30s cooldown).
func TestBruteForce_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("correct credentials succeed immediately", func(t *testing.T) {
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("10 failed attempts trigger lockout", func(t *testing.T) {
		// Use a unique username to avoid state pollution from other subtests
		for i := 0; i < 10; i++ {
			doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				formBody("username", "locktest_user", "password", "wrong"), cookie)
		}
		// 11th attempt should see lockout message
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "locktest_user", "password", "correct"), cookie)
		assert.Contains(t, w.Body.String(), "Account locked")
	})
}

// TestBruteForce_Hard verifies progressive lockout tiers (3→5min, 6→30min, 9→2hr).
func TestBruteForce_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("correct credentials succeed before any failures", func(t *testing.T) {
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("3 consecutive failures lock out even correct password", func(t *testing.T) {
		// Use pablo's real credentials; fail 3 times to trigger first lockout tier
		for i := 0; i < 3; i++ {
			doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				formBody("username", pabloUsername, "password", "wrong"), cookie)
		}
		// Correct password must now be rejected — this is the meaningful lockout check
		w := doModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			formBody("username", pabloUsername, "password", pabloPassword), cookie)
		assert.Contains(t, w.Body.String(), `"success":false`)
	})
}
