package logmonitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func loginAuditMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "login-audit",
		Name:        "Login Audit",
		Description: "Review how authentication attempts are logged and alerted.",
		Category:    "Security Logging and Monitoring Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
		},
		Hints: [4]string{
			"Failed authentication attempts are security events.",
			"Check whether both success and failure are logged.",
			"Useful logs need actor, source, outcome, and time.",
			"Hard mode creates an alert after repeated failures.",
		},
	}
}

func serveLoginAudit(m *LogMonitoringModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		laHandleAttempt(m, w, r)
		return
	}
	fmt.Fprint(w, laRenderForm("", laRecentEvents(m)))
}

func laHandleAttempt(m *LogMonitoringModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	ip := r.RemoteAddr
	var user database.User
	success := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error == nil

	switch m.difficulty {
	case core.Easy:
		if success {
			laCreateEvent(m, user.Username, "login", "success", ip, "info", "login succeeded")
		}
	case core.Medium:
		if success {
			laCreateEvent(m, user.Username, "login", "success", "", "info", "login succeeded")
		} else {
			laCreateEvent(m, "unknown", "login", "failure", "", "warning", "login failed")
		}
	case core.Hard:
		if success {
			laCreateEvent(m, user.Username, "login", "success", ip, "info", "login succeeded")
		} else {
			laCreateEvent(m, username, "login", "failure", ip, "warning", "login failed for "+username)
			if laRecentFailureCount(m, username) >= 3 {
				laCreateEvent(m, username, "alert", "triggered", ip, "critical", "multiple failed login attempts")
			}
		}
	}

	resp, _ := json.Marshal(map[string]any{"success": success})
	fmt.Fprint(w, laRenderForm(`<pre class="output">`+string(resp)+`</pre>`, laRecentEvents(m)))
}

func laCreateEvent(m *LogMonitoringModule, username, eventType, outcome, ip, severity, message string) {
	m.store.DB().Create(&database.AuditEvent{
		Username:  username,
		EventType: eventType,
		Outcome:   outcome,
		IPAddress: ip,
		Severity:  severity,
		Message:   message,
		CreatedAt: time.Now(),
	})
}

func laRecentFailureCount(m *LogMonitoringModule, username string) int64 {
	var count int64
	m.store.DB().Model(&database.AuditEvent{}).
		Where("username = ? AND event_type = ? AND outcome = ? AND created_at > ?", username, "login", "failure", time.Now().Add(-5*time.Minute)).
		Count(&count)
	return count
}

func laRecentEvents(m *LogMonitoringModule) string {
	var events []database.AuditEvent
	m.store.DB().Order("id desc").Limit(8).Find(&events)
	data, _ := json.MarshalIndent(map[string]any{"recent_events": events}, "", "  ")
	return `<pre class="output">` + string(data) + `</pre>`
}

func laRenderForm(output, events string) string {
	page := `<div class="vuln-form">
<h3>Login Audit</h3>
<form method="POST">
<label>Username: <input type="text" name="username" /></label><br/>
<label>Password: <input type="password" name="password" /></label><br/>
<input type="submit" value="Sign In" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page + events
}
