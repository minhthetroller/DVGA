package logmonitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func logTamperingMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "log-tampering",
		Name:        "Audit Log Viewer",
		Description: "View and manage audit log records.",
		Category:    "Security Logging and Monitoring Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
		},
		Hints: [4]string{
			"Audit logs should not be controlled by the client.",
			"Can you delete or forge a log entry?",
			"Client-supplied role metadata is not authorization.",
			"Hard mode appends server-generated audit records only.",
		},
	}
}

func serveLogTampering(m *LogMonitoringModule, w http.ResponseWriter, r *http.Request) {
	output := ""
	if r.Method == http.MethodPost {
		output = ltHandleAction(m, r)
	}
	fmt.Fprint(w, ltRenderPage(output, ltRecentEvents(m)))
}

func ltHandleAction(m *LogMonitoringModule, r *http.Request) string {
	action := r.FormValue("action")
	switch m.difficulty {
	case core.Easy:
		return ltApplyClientAction(m, r, action)
	case core.Medium:
		if r.FormValue("role") != "admin" {
			return `<div class="error">Forbidden.</div>`
		}
		return ltApplyClientAction(m, r, action)
	case core.Hard:
		cookie, err := r.Cookie("session_id")
		if err != nil {
			return `<div class="error">Unauthenticated.</div>`
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil || sess.Role != "admin" {
			return `<div class="error">Forbidden.</div>`
		}
		if action == "append" {
			m.store.DB().Create(&database.AuditEvent{
				Username:  sess.Username,
				EventType: "log_review",
				Outcome:   "success",
				IPAddress: r.RemoteAddr,
				Severity:  "info",
				Message:   "admin reviewed audit log",
				CreatedAt: time.Now(),
			})
			return `<div class="output">Server-generated review event appended.</div>`
		}
		return `<div class="error">Audit logs are append-only.</div>`
	}
	return ""
}

func ltApplyClientAction(m *LogMonitoringModule, r *http.Request, action string) string {
	switch action {
	case "append":
		m.store.DB().Create(&database.AuditEvent{
			Username:  r.FormValue("username"),
			EventType: r.FormValue("event_type"),
			Outcome:   r.FormValue("outcome"),
			IPAddress: r.FormValue("ip_address"),
			Severity:  r.FormValue("severity"),
			Message:   r.FormValue("message"),
			CreatedAt: time.Now(),
		})
		return `<div class="output">Client-supplied audit entry appended.</div>`
	case "delete":
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			return `<div class="error">Invalid log id.</div>`
		}
		m.store.DB().Delete(&database.AuditEvent{}, id)
		return `<div class="output">Audit entry deleted.</div>`
	default:
		return `<div class="error">Unknown action.</div>`
	}
}

func ltRecentEvents(m *LogMonitoringModule) string {
	var events []database.AuditEvent
	m.store.DB().Order("id desc").Limit(10).Find(&events)
	data, _ := json.MarshalIndent(map[string]any{"audit_events": events}, "", "  ")
	return `<pre class="output">` + string(data) + `</pre>`
}

func ltRenderPage(output, events string) string {
	page := `<div class="vuln-form">
<h3>Audit Log Viewer</h3>
<form method="POST">
<input type="hidden" name="action" value="append" />
<h4>Append Entry</h4>
<label>Role: <input type="text" name="role" value="user" /></label><br/>
<label>Username: <input type="text" name="username" /></label><br/>
<label>Event Type: <input type="text" name="event_type" value="login" /></label><br/>
<label>Outcome: <input type="text" name="outcome" value="success" /></label><br/>
<label>Severity: <input type="text" name="severity" value="info" /></label><br/>
<label>IP Address: <input type="text" name="ip_address" value="127.0.0.1" /></label><br/>
<label>Message: <input type="text" name="message" size="60" /></label><br/>
<input type="submit" value="Append Log" />
</form>
<form method="POST" style="margin-top:1rem">
<input type="hidden" name="action" value="delete" />
<label>Role: <input type="text" name="role" value="user" /></label><br/>
<label>Log ID: <input type="text" name="id" /></label>
<input type="submit" value="Delete Log" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page + events
}
