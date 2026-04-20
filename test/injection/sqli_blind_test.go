package injectiontest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestSQLiBlind_Easy verifies the easy difficulty is fully vulnerable to blind SQLi.
func TestSQLiBlind_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("known username reports unavailable", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet, "/?username=admin", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":false`)
	})

	t.Run("unknown username reports available", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet, "/?username=doesnotexist", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":true`)
	})

	t.Run("OR TRUE injection always reports unavailable", func(t *testing.T) {
		// admin' OR '1'='1 — the WHERE clause is always true, always returns a row
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=doesnotexist%27+OR+%271%27%3D%271", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":false`)
	})

	t.Run("AND FALSE injection always reports available", func(t *testing.T) {
		// admin' AND '1'='2 — always false, no row returned
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27+AND+%271%27%3D%272", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":true`)
	})

	t.Run("UNION injection executes without error", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27+UNION+SELECT+1--", nil, cookie)
		// Should get a valid JSON response (not an error page)
		assert.Contains(t, w.Body.String(), "available")
	})
}

// TestSQLiBlind_Medium verifies quote escaping partially mitigates blind SQLi.
func TestSQLiBlind_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("known username still reports unavailable", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet, "/?username=admin", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":false`)
	})

	t.Run("quote escaping prevents simple OR injection", func(t *testing.T) {
		// admin' OR '1'='1  → after escaping: admin\' OR \'1\'=\'1 — no longer valid SQL injection
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27+OR+%271%27%3D%271", nil, cookie)
		// The escaped query will not match any real username, so available: true
		assert.Contains(t, w.Body.String(), `"available":true`)
	})
}

// TestSQLiBlind_Hard verifies parameterized queries fully prevent blind SQLi.
func TestSQLiBlind_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	token := app.MustLogin(testutil.AdminUsername, testutil.AdminPassword)
	cookie := app.SessionCookie(token)

	t.Run("exact username match still works", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet, "/?username=admin", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":false`)
	})

	t.Run("OR TRUE injection treated as literal string — reports available", func(t *testing.T) {
		// With parameterized query, the full string "admin' OR '1'='1" is treated literally
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27+OR+%271%27%3D%271", nil, cookie)
		// No user has that exact username, so available: true
		assert.Contains(t, w.Body.String(), `"available":true`)
	})

	t.Run("UNION injection does not execute", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27+UNION+SELECT+1--", nil, cookie)
		// Treated as a literal string search; no such user exists
		assert.Contains(t, w.Body.String(), `"available":true`)
	})

	t.Run("comment injection does not bypass lookup", func(t *testing.T) {
		w := testutil.DoModuleRequest(t, app, "sqli-blind", http.MethodGet,
			"/?username=admin%27--", nil, cookie)
		assert.Contains(t, w.Body.String(), `"available":true`)
	})
}
