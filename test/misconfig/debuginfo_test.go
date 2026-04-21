package misconfigtest

import (
	"net/http"
	"runtime"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestDebugInfo_Easy verifies Go version, env vars, and stack traces are exposed.
func TestDebugInfo_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("Server header exposes Go version", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.Equal(t, "Go/"+runtime.Version(), w.Header().Get("Server"))
	})

	t.Run("response contains Go version", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), runtime.Version())
	})

	t.Run("response contains environment variables section", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "Environment Variables")
	})

	t.Run("action=error triggers stack trace", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/?action=error", nil, cookie)
		body := w.Body.String()
		assert.Contains(t, body, "Stack Trace")
		assert.Contains(t, body, "goroutine")
	})
}

// TestDebugInfo_Medium verifies only Go version and OS/arch are shown; no env vars.
func TestDebugInfo_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("response contains Go version", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), runtime.Version())
	})

	t.Run("no environment variables exposed", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.NotContains(t, w.Body.String(), "Environment Variables")
	})

	t.Run("no Server header set", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.Empty(t, w.Header().Get("Server"))
	})

	t.Run("action=error shows DB error but no stack trace", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/?action=error", nil, cookie)
		body := w.Body.String()
		assert.Contains(t, body, "Error")
		assert.NotContains(t, body, "Stack Trace")
	})
}

// TestDebugInfo_Hard verifies only generic message is returned.
func TestDebugInfo_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("response only shows generic message", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		assert.Contains(t, body, "Server is running")
		assert.NotContains(t, body, runtime.Version())
	})

	t.Run("no environment variables", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/", nil, cookie)
		assert.NotContains(t, w.Body.String(), "Environment Variables")
	})

	t.Run("action=error returns generic error, no DB info", func(t *testing.T) {
		w := doModuleRequest(t, app, "debug-info", http.MethodGet, "/?action=error", nil, cookie)
		body := w.Body.String()
		assert.Contains(t, body, "An error occurred")
		assert.NotContains(t, body, "nonexistent")
		assert.NotContains(t, body, "goroutine")
	})
}
