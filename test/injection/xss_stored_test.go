package injectiontest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestXSSStored_Easy verifies payload is stored and rendered verbatim.
func TestXSSStored_Easy(t *testing.T) {
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("normal review stored and displayed", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "testuser", "review", "Great product!"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "Great product!")
	})

	t.Run("script tag stored and rendered verbatim", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<script>alert('xss')</script>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "<script>alert('xss')</script>")
	})

	t.Run("img onerror payload stored and rendered", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<img src=x onerror=alert(1)>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "<img src=x onerror=alert(1)>")
	})
}

// TestXSSStored_Medium verifies <script> is stripped before storage but other vectors pass.
func TestXSSStored_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("script tag stripped before storage", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<script>alert('xss')</script>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>")
		assert.NotContains(t, body, "</script>")
	})

	t.Run("uppercase SCRIPT tag also stripped", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<SCRIPT>alert(1)</SCRIPT>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		assert.NotContains(t, w.Body.String(), "<SCRIPT>")
	})

	t.Run("img onerror NOT stripped — still stored and rendered", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<img src=x onerror=alert(1)>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		assert.Contains(t, w.Body.String(), "<img")
		assert.Contains(t, w.Body.String(), "onerror")
	})
}

// TestXSSStored_Hard verifies output is HTML-escaped on render and CSP header is set.
func TestXSSStored_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("script tag HTML-escaped on render", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<script>alert('xss')</script>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>alert")
		assert.Contains(t, body, "&lt;script&gt;")
	})

	t.Run("img onerror HTML-escaped on render", func(t *testing.T) {
		doModuleRequest(t, app, "xss-stored", http.MethodPost, "/",
			formBody("name", "attacker", "review", "<img src=x onerror=alert(1)>"), cookie)
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		body := w.Body.String()
		assert.NotContains(t, body, "<img src=x onerror")
		assert.Contains(t, body, "&lt;img")
	})

	t.Run("CSP header is set on GET", func(t *testing.T) {
		w := doModuleRequest(t, app, "xss-stored", http.MethodGet, "/", nil, cookie)
		csp := w.Header().Get("Content-Security-Policy")
		assert.Contains(t, csp, "script-src")
	})
}
