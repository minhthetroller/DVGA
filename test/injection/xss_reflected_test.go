package injectiontest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestXSSReflected_Easy verifies payload is reflected verbatim in the response.
func TestXSSReflected_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	tests := []struct {
		name    string
		payload string
		wantIn  string
	}{
		{
			name:    "normal search term reflected",
			payload: "laptop",
			wantIn:  "laptop",
		},
		{
			name:    "script tag reflected verbatim",
			payload: "%3Cscript%3Ealert(1)%3C%2Fscript%3E", // <script>alert(1)</script>
			wantIn:  "<script>alert(1)</script>",
		},
		{
			name:    "img onerror payload reflected",
			payload: "%3Cimg+onerror%3Dalert(1)+src%3Dx%3E", // <img onerror=alert(1) src=x>
			wantIn:  "<img",
		},
		{
			name:    "svg onload payload reflected",
			payload: "%3Csvg+onload%3Dalert(1)%3E",
			wantIn:  "<svg",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet, "/?q="+tc.payload, nil, cookie)
			assert.Contains(t, w.Body.String(), tc.wantIn)
		})
	}
}

// TestXSSReflected_Medium verifies <script> tags are stripped but other vectors pass.
func TestXSSReflected_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("normal search works", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet, "/?q=laptop", nil, cookie)
		assert.Contains(t, w.Body.String(), "laptop")
	})

	t.Run("script tag stripped from response", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, cookie)
		assert.NotContains(t, w.Body.String(), "<script>")
	})

	t.Run("img onerror payload still passes through", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=%3Cimg+onerror%3Dalert(1)+src%3Dx%3E", nil, cookie)
		assert.Contains(t, w.Body.String(), "<img")
		assert.Contains(t, w.Body.String(), "onerror")
	})

	t.Run("svg onload payload still passes through", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=%3Csvg+onload%3Dalert(1)%3E", nil, cookie)
		assert.Contains(t, w.Body.String(), "<svg")
	})
}

// TestXSSReflected_Hard verifies all HTML is escaped and CSP header is set.
func TestXSSReflected_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("normal search still works", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet, "/?q=laptop", nil, cookie)
		assert.Contains(t, w.Body.String(), "laptop")
	})

	t.Run("script tag HTML-escaped in response", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, cookie)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>")
		assert.Contains(t, body, "&lt;script&gt;")
	})

	t.Run("img onerror payload is HTML-escaped", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=%3Cimg+onerror%3Dalert(1)+src%3Dx%3E", nil, cookie)
		body := w.Body.String()
		assert.NotContains(t, body, "<img")
		assert.Contains(t, body, "&lt;img")
	})

	t.Run("CSP header is set", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "xss-reflected", http.MethodGet,
			"/?q=test", nil, cookie)
		csp := w.Header().Get("Content-Security-Policy")
		assert.Contains(t, csp, "script-src")
	})
}
