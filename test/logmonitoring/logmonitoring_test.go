package logmonitoringtest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/internal/database"

	"github.com/stretchr/testify/assert"
)

func TestLogMonitoringRegisteredUnderExpectedCategory(t *testing.T) {
	app := newTestApp(t)
	cats := app.registry.Categories(core.Easy)

	var ids []string
	for _, mod := range cats["Security Logging and Monitoring Failures"] {
		ids = append(ids, mod.Meta().ID)
	}

	assert.ElementsMatch(t, []string{"login-audit", "log-tampering"}, ids)
}

func TestLoginAuditByDifficulty(t *testing.T) {
	app := newTestApp(t)

	beforeFailures := auditCount(app, "pablo", "login", "failure")
	doModuleRequest(t, app, "login-audit", http.MethodPost, "/", formBody("username", "pablo", "password", "wrong"))
	assert.Equal(t, beforeFailures, auditCount(app, "pablo", "login", "failure"))

	beforeSuccess := auditCount(app, "admin", "login", "success")
	doModuleRequest(t, app, "login-audit", http.MethodPost, "/", formBody("username", "admin", "password", "admin"))
	assert.Equal(t, beforeSuccess+1, auditCount(app, "admin", "login", "success"))

	app.setDifficulty(core.Medium)
	doModuleRequest(t, app, "login-audit", http.MethodPost, "/", formBody("username", "pablo", "password", "wrong"))
	assert.GreaterOrEqual(t, auditCount(app, "unknown", "login", "failure"), int64(1))
	var mediumFailure database.AuditEvent
	app.store.DB().Where("username = ? AND event_type = ? AND outcome = ?", "unknown", "login", "failure").Last(&mediumFailure)
	assert.Empty(t, mediumFailure.IPAddress)

	app.setDifficulty(core.Hard)
	for i := 0; i < 3; i++ {
		doModuleRequest(t, app, "login-audit", http.MethodPost, "/", formBody("username", "pablo", "password", "wrong"))
	}
	assert.GreaterOrEqual(t, auditCount(app, "pablo", "login", "failure"), int64(3))
	assert.GreaterOrEqual(t, auditCount(app, "pablo", "alert", "triggered"), int64(1))
	var hardFailure database.AuditEvent
	app.store.DB().Where("username = ? AND event_type = ? AND outcome = ?", "pablo", "login", "failure").Last(&hardFailure)
	assert.NotEmpty(t, hardFailure.IPAddress)
}

func TestLogTamperingByDifficulty(t *testing.T) {
	app := newTestApp(t)

	doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody(
		"action", "append",
		"username", "attacker",
		"event_type", "login",
		"outcome", "success",
		"severity", "info",
		"ip_address", "10.0.0.66",
		"message", "forged success",
	))
	assert.GreaterOrEqual(t, auditCount(app, "attacker", "login", "success"), int64(1))

	var first database.AuditEvent
	app.store.DB().Order("id asc").First(&first)
	doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody("action", "delete", "id", "1"))
	var deletedCount int64
	app.store.DB().Model(&database.AuditEvent{}).Where("id = ?", first.ID).Count(&deletedCount)
	assert.Equal(t, int64(0), deletedCount)

	app.setDifficulty(core.Medium)
	w := doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody(
		"action", "append",
		"role", "user",
		"username", "medium-user",
		"event_type", "login",
		"outcome", "success",
	))
	assert.Contains(t, w.Body.String(), "Forbidden")
	w = doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody(
		"action", "append",
		"role", "admin",
		"username", "medium-admin",
		"event_type", "login",
		"outcome", "success",
		"severity", "info",
	))
	assert.Contains(t, w.Body.String(), "Client-supplied")
	assert.GreaterOrEqual(t, auditCount(app, "medium-admin", "login", "success"), int64(1))

	app.setDifficulty(core.Hard)
	adminToken := app.sessions.Create(1, "admin", "admin")
	adminCookie := &http.Cookie{Name: "session_id", Value: adminToken}
	w = doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody("action", "delete", "id", "2"), adminCookie)
	assert.Contains(t, w.Body.String(), "append-only")

	w = doModuleRequest(t, app, "log-tampering", http.MethodPost, "/", formBody(
		"action", "append",
		"username", "forged-hard",
		"event_type", "login",
		"outcome", "success",
	), adminCookie)
	assert.Contains(t, w.Body.String(), "Server-generated")
	assert.Equal(t, int64(0), auditCount(app, "forged-hard", "login", "success"))
	assert.GreaterOrEqual(t, auditCount(app, "admin", "log_review", "success"), int64(1))
}

func auditCount(app *testApp, username, eventType, outcome string) int64 {
	var count int64
	app.store.DB().Model(&database.AuditEvent{}).
		Where("username = ? AND event_type = ? AND outcome = ?", username, eventType, outcome).
		Count(&count)
	return count
}
