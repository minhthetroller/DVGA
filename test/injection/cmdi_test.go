package injectiontest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestCMDi_Easy verifies the easy difficulty executes shell commands without restriction.
func TestCMDi_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("valid IP is accepted", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1"), cookie)
		// ping output should appear
		assert.Contains(t, w.Body.String(), "127.0.0.1")
	})

	t.Run("semicolon chaining executes second command", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1; echo INJECTED_MARKER"), cookie)
		assert.Contains(t, w.Body.String(), "INJECTED_MARKER")
	})

	t.Run("AND chaining executes second command", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1 && echo ANDMARKER"), cookie)
		assert.Contains(t, w.Body.String(), "ANDMARKER")
	})

	t.Run("pipe injection executes second command", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1 | echo PIPEMARKER"), cookie)
		assert.Contains(t, w.Body.String(), "PIPEMARKER")
	})

	t.Run("subshell injection executes embedded command", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "$(echo SUBSHELL_MARKER)"), cookie)
		assert.Contains(t, w.Body.String(), "SUBSHELL_MARKER")
	})
}

// TestCMDi_Medium verifies that && and ; are stripped but | and $() still work.
func TestCMDi_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("valid IP still works", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1"), cookie)
		assert.Contains(t, w.Body.String(), "127.0.0.1")
	})

	t.Run("semicolon stripped — injection does not execute", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1; echo SHOULDNOTAPPEAR"), cookie)
		assert.NotContains(t, w.Body.String(), "SHOULDNOTAPPEAR")
	})

	t.Run("&& stripped — injection does not execute", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1 && echo SHOULDNOTAPPEAR"), cookie)
		assert.NotContains(t, w.Body.String(), "SHOULDNOTAPPEAR")
	})

	t.Run("pipe NOT stripped — injection still executes", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1 | echo PIPEMARKER_MED"), cookie)
		assert.Contains(t, w.Body.String(), "PIPEMARKER_MED")
	})

	t.Run("subshell NOT stripped — injection still executes", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "$(echo SUBSHELL_MED)"), cookie)
		assert.Contains(t, w.Body.String(), "SUBSHELL_MED")
	})
}

// TestCMDi_Hard verifies that only valid IP addresses are accepted and no shell is used.
func TestCMDi_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("valid IP is accepted and runs ping", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1"), cookie)
		assert.Contains(t, w.Body.String(), "127.0.0.1")
	})

	t.Run("non-IP hostname rejected", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "not-an-ip"), cookie)
		assert.Contains(t, w.Body.String(), "Invalid IP")
	})

	t.Run("semicolon injection rejected by IP validation", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1; echo HARD_INJECT"), cookie)
		assert.Contains(t, w.Body.String(), "Invalid IP")
		assert.NotContains(t, w.Body.String(), "HARD_INJECT")
	})

	t.Run("pipe injection rejected", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "127.0.0.1 | echo HARD_PIPE"), cookie)
		assert.Contains(t, w.Body.String(), "Invalid IP")
		assert.NotContains(t, w.Body.String(), "HARD_PIPE")
	})

	t.Run("subshell injection rejected", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "cmdi", http.MethodPost, "/",
			testutil.FormBody("host", "$(echo HARD_SUB)"), cookie)
		assert.Contains(t, w.Body.String(), "Invalid IP")
		assert.NotContains(t, w.Body.String(), "HARD_SUB")
	})
}
