package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// TestReportGenerator_Easy verifies no row limit — all rows returned.
func TestReportGenerator_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("all orders returned regardless of max_rows", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		// Seed has 6 orders; easy mode returns all regardless of max_rows=1
		count, _ := m["count"].(float64)
		assert.GreaterOrEqual(t, int(count), 5)
	})

	t.Run("invalid table rejected", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"users","max_rows":100}`, gordonCookie)
		assertStatus(t, resp, http.StatusBadRequest)
	})
}

// TestReportGenerator_Medium verifies max_rows is advertised but ignored.
func TestReportGenerator_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("max_rows=1 but all rows still returned", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		count, _ := m["count"].(float64)
		assert.GreaterOrEqual(t, int(count), 5)
	})

	t.Run("note field explains limit is ignored", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":1}`, gordonCookie)
		body := readBody(t, resp)
		assert.Contains(t, body, "ignored")
	})
}

// TestReportGenerator_Hard verifies max_rows capped at 1000.
func TestReportGenerator_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("max_rows=2 is enforced", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":2}`, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		count, _ := m["count"].(float64)
		assert.Equal(t, 2, int(count))
	})

	t.Run("max_rows over 1000 is capped to 1000", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/reports/generate",
			`{"table":"orders","max_rows":5000}`, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		m := parseJSON(t, body)
		capped, _ := m["capped_at"].(float64)
		assert.Equal(t, 1000, int(capped))
	})
}

// TestNotificationBlast_Easy verifies no rate limit.
func TestNotificationBlast_Easy(t *testing.T) {
	app := newTestApp(t)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"test@example.com","body":"hello"}`)
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("multiple notifications allowed without limit", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"target@example.com","body":"spam"}`, gordonCookie)
			assertStatus(t, resp, http.StatusOK)
		}
	})
}

// TestNotificationBlast_Medium verifies IP rate limit (bypassable via X-Forwarded-For).
func TestNotificationBlast_Medium(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("IP rate limit enforced after 10 requests", func(t *testing.T) {
		// Send 10 — all allowed
		for i := 0; i < 10; i++ {
			resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"r@example.com","body":"hi"}`,
				map[string]string{"X-Forwarded-For": "1.2.3.4"}, gordonCookie)
			assertStatus(t, resp, http.StatusOK)
		}
		// 11th request should be rate-limited
		resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"hi"}`,
			map[string]string{"X-Forwarded-For": "1.2.3.4"}, gordonCookie)
		assertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("rate limit bypassable by changing X-Forwarded-For", func(t *testing.T) {
		// After exhausting 1.2.3.4 above, switching IP bypasses the limit
		resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"bypass"}`,
			map[string]string{"X-Forwarded-For": "9.9.9.9"}, gordonCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestNotificationBlast_Hard verifies per-account quota (max 5 per session).
func TestNotificationBlast_Hard(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	gordonToken := app.mustLogin(gordonUsername, gordonPassword)
	gordonCookie := app.sessionCookie(gordonToken)

	t.Run("quota of 5 enforced per account", func(t *testing.T) {
		// Send 5 — all should succeed
		for i := 0; i < 5; i++ {
			resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
				`{"recipient":"r@example.com","body":"msg"}`, gordonCookie)
			assertStatus(t, resp, http.StatusOK)
		}
		// 6th should be rejected
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"msg"}`, gordonCookie)
		assertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("changing X-Forwarded-For does NOT bypass account quota", func(t *testing.T) {
		// Gordon's quota is exhausted from above; IP spoofing won't help
		resp := doAPIRequestWithHeader(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"bypass"}`,
			map[string]string{"X-Forwarded-For": "9.9.9.9"}, gordonCookie)
		// Still rate limited because it's per account, not per IP
		assertStatus(t, resp, http.StatusTooManyRequests)
	})

	t.Run("different account has its own quota", func(t *testing.T) {
		// Pablo hasn't sent anything yet
		pabloToken := app.mustLogin(pabloUsername, pabloPassword)
		pabloCookie := app.sessionCookie(pabloToken)
		resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
			`{"recipient":"r@example.com","body":"pablo msg"}`, pabloCookie)
		assertStatus(t, resp, http.StatusOK)
	})
}

// TestNotificationBlast_Hard_remaining verifies remaining count in response.
func TestNotificationBlast_Hard_remaining(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	leetToken := app.mustLogin(leetUsername, leetPassword)
	leetCookie := app.sessionCookie(leetToken)

	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/notifications/send",
		`{"recipient":"r@example.com","body":"first"}`, leetCookie)
	assertStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	m := parseJSON(t, body)
	remaining, _ := m["remaining"].(float64)
	assert.Equal(t, 4, int(remaining)) // 5 - 1 = 4
}

