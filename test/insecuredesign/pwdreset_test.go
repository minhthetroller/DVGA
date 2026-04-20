package insecuredesigntest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestPwdReset_Easy verifies no attempt limiting — security answer accepted directly.
func TestPwdReset_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("username lookup succeeds", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "lookup", "username", "gordonb"), cookie)
		assert.Contains(t, w.Body.String(), "colour")
	})

	t.Run("wrong answer rejected", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "gordonb", "answer", "wronganswer", "new_password", "newpass"), cookie)
		assert.Contains(t, w.Body.String(), "Wrong answer")
	})

	t.Run("correct answer resets password immediately", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "gordonb", "answer", "blue", "new_password", "newpass123"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("no attempt limit — many wrong guesses allowed", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
				testutil.FormBody("action", "answer", "username", "pablo", "answer", "wronganswer", "new_password", "x"), cookie)
		}
		// 21st attempt with correct answer should still work
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "pablo", "answer", "buddy", "new_password", "newpass"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})
}

// TestPwdReset_Medium verifies 15-attempt lockout per minute.
func TestPwdReset_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("correct answer still works", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "gordonb", "answer", "blue", "new_password", "newpass"), cookie)
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("15 failed attempts trigger lockout", func(t *testing.T) {
		// Use a separate user to avoid polluting other subtests
		for i := 0; i < 15; i++ {
			testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
				testutil.FormBody("action", "answer", "username", "pablo", "answer", "wronganswer", "new_password", "x"), cookie)
		}
		// 16th attempt should be rate-limited
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "pablo", "answer", "buddy", "new_password", "newpass"), cookie)
		assert.Contains(t, w.Body.String(), "Too many attempts")
	})
}

// TestPwdReset_Hard verifies 3-attempt lockout with token-based reset flow.
func TestPwdReset_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("correct answer issues a reset token", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "gordonb", "answer", "blue", "new_password", "ignored"), cookie)
		// Hard mode returns a token, not an immediate reset
		body := w.Body.String()
		assert.NotContains(t, body, `"success":true`) // no direct reset
		// Should show the token form
		assert.Contains(t, body, "token")
	})

	t.Run("3 failed attempts trigger lockout", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
				testutil.FormBody("action", "answer", "username", "pablo", "answer", "wronganswer", "new_password", "x"), cookie)
		}
		// 4th attempt should be locked
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "answer", "username", "pablo", "answer", "buddy", "new_password", "x"), cookie)
		assert.Contains(t, w.Body.String(), "locked")
	})

	t.Run("invalid token rejected on use_token", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "pwd-reset", http.MethodPost, "/",
			testutil.FormBody("action", "use_token", "username", "gordonb", "token", "invalidtoken", "new_password", "newpass"), cookie)
		assert.Contains(t, w.Body.String(), "Invalid or expired token")
	})
}
