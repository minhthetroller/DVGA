package insecuredesigntest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestBruteForce_Easy verifies no rate limiting — unlimited login attempts allowed.
func TestBruteForce_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("correct credentials succeed", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("wrong credentials return invalid message", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "gordonb", "password", "wrong"), cookie)
		assert.Contains(t, w.Body.String(), `"success":false`)
	})

	t.Run("20 consecutive failed attempts allowed — no lockout", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				testutil.FormBody("username", "pablo", "password", "wrong"), cookie)
		}
		// After 20 failed attempts, correct password still works
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "pablo", "password", "letmein"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})
}

// TestBruteForce_Medium verifies lockout after 10 failed attempts (30s cooldown).
func TestBruteForce_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("correct credentials succeed immediately", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("10 failed attempts trigger lockout", func(t *testing.T) {
		// Use a unique username to avoid state pollution from other subtests
		for i := 0; i < 10; i++ {
			testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				testutil.FormBody("username", "locktest_user", "password", "wrong"), cookie)
		}
		// 11th attempt should see lockout message
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "locktest_user", "password", "correct"), cookie)
		assert.Contains(t, w.Body.String(), "Account locked")
	})
}

// TestBruteForce_Hard verifies progressive lockout tiers (3→5min, 6→30min, 9→2hr).
func TestBruteForce_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("correct credentials succeed before any failures", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", "gordonb", "password", "abc123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("3 consecutive failures lock out even correct password", func(t *testing.T) {
		// Use pablo's real credentials; fail 3 times to trigger first lockout tier
		for i := 0; i < 3; i++ {
			testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
				testutil.FormBody("username", testutil.PabloUsername, "password", "wrong"), cookie)
		}
		// Correct password must now be rejected — this is the meaningful lockout check
		w := testutil.DoModuleRequest(t, app, "brute-force", http.MethodPost, "/",
			testutil.FormBody("username", testutil.PabloUsername, "password", testutil.PabloPassword), cookie)
		assert.Contains(t, w.Body.String(), `"success":false`)
	})
}
