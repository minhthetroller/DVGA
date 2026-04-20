package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/test/testutil"

	"github.com/stretchr/testify/assert"
)

// TestReportGenerator_Easy verifies no row limit — all rows returned.
func TestReportGenerator_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("all orders returned regardless of max_rows", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		// Seed has 6 orders; easy mode returns all regardless of max_rows=1
		count, _ := m["count"].(float64)
		assert.GreaterOrEqual(t, int(count), 5)
	})

	t.Run("invalid table rejected", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"users","max_rows":100}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusBadRequest)
	})
}

// TestReportGenerator_Medium verifies max_rows is advertised but ignored.
func TestReportGenerator_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("max_rows=1 but all rows still returned", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		count, _ := m["count"].(float64)
		assert.GreaterOrEqual(t, int(count), 5)
	})

	t.Run("note field explains limit is ignored", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		body := testutil.ReadBody(t, resp)
		assert.Contains(t, body, "ignored")
	})
}

// TestReportGenerator_Hard verifies max_rows capped at 1000.
func TestReportGenerator_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("max_rows=2 is enforced", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":2}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		count, _ := m["count"].(float64)
		assert.Equal(t, 2, int(count))
	})

	t.Run("max_rows over 1000 is capped to 1000", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":5000}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
		body := testutil.ReadBody(t, resp)
		m := testutil.ParseJSON(t, body)
		capped, _ := m["capped_at"].(float64)
		assert.Equal(t, 1000, int(capped))
	})
}

// TestNotificationBlast_Easy verifies no rate limit.
func TestNotificationBlast_Easy(t *testing.T) {
	app := testutil.NewTestApp(t)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"test@example.com","body":"hello"}`)
		testutil.AssertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("multiple notifications allowed without limit", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"target@example.com","body":"spam"}`, gordonCookie)
			testutil.AssertStatus(t, resp, http.StatusOK)
		}
	})
}

// TestNotificationBlast_Medium verifies IP rate limit (bypassable via X-Forwarded-For).
func TestNotificationBlast_Medium(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Medium)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("IP rate limit enforced after 10 requests", func(t *testing.T) {
		// Send 10 — all allowed
		for i := 0; i < 10; i++ {
			resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"r@example.com","body":"hi"}`,
				map[string]string{"X-Forwarded-For": "1.2.3.4"}, gordonCookie)
			testutil.AssertStatus(t, resp, http.StatusOK)
		}
		// 11th request should be rate-limited
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"hi"}`,
			map[string]string{"X-Forwarded-For": "1.2.3.4"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("rate limit bypassable by changing X-Forwarded-For", func(t *testing.T) {
		// After exhausting 1.2.3.4 above, switching IP bypasses the limit
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"bypass"}`,
			map[string]string{"X-Forwarded-For": "9.9.9.9"}, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestNotificationBlast_Hard verifies per-account quota (max 5 per session).
func TestNotificationBlast_Hard(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	gordonToken := app.MustLogin(testutil.GordonUsername, testutil.GordonPassword)
	gordonCookie := app.SessionCookie(gordonToken)

	t.Run("quota of 5 enforced per account", func(t *testing.T) {
		// Send 5 — all should succeed
		for i := 0; i < 5; i++ {
			resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"r@example.com","body":"msg"}`, gordonCookie)
			testutil.AssertStatus(t, resp, http.StatusOK)
		}
		// 6th should be rejected
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"msg"}`, gordonCookie)
		testutil.AssertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("changing X-Forwarded-For does NOT bypass account quota", func(t *testing.T) {
		// Gordon's quota is exhausted from above; IP spoofing won't help
		resp := testutil.DoAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"bypass"}`,
			map[string]string{"X-Forwarded-For": "9.9.9.9"}, gordonCookie)
		// Still rate limited because it's per account, not per IP
		testutil.AssertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("different account has its own quota", func(t *testing.T) {
		// Pablo hasn't sent anything yet
		pabloToken := app.MustLogin(testutil.PabloUsername, testutil.PabloPassword)
		pabloCookie := app.SessionCookie(pabloToken)
		resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"pablo msg"}`, pabloCookie)
		testutil.AssertStatus(t, resp, http.StatusOK)
	})
}

// TestNotificationBlast_Hard_remaining verifies remaining count in response.
func TestNotificationBlast_Hard_remaining(t *testing.T) {
	app := testutil.NewTestApp(t)
	app.SetDifficulty(core.Hard)
	leetToken := app.MustLogin(testutil.LeetUsername, testutil.LeetPassword)
	leetCookie := app.SessionCookie(leetToken)

	resp := testutil.DoAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
		`{"recipient":"r@example.com","body":"first"}`, leetCookie)
	testutil.AssertStatus(t, resp, http.StatusOK)
	body := testutil.ReadBody(t, resp)
	m := testutil.ParseJSON(t, body)
	remaining, _ := m["remaining"].(float64)
	assert.Equal(t, 4, int(remaining)) // 5 - 1 = 4
}

