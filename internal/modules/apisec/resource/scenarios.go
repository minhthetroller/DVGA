package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Report Generator ---

func reportGeneratorMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "report-generator",
		Name:     "Report Generator",
		Category: "Unrestricted Resource Consumption",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		},
		Hints: [4]string{
			"POST a report generation request.",
			"Try requesting a very large report.",
			"Is there a limit on how many rows are returned?",
			"Hard mode enforces max_rows=1000 and a timeout.",
		},
	}
}

func serveReportGeneratorInfo(m *ResourceModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Report Generator</h3>
<p>POST to <code>/api/v1/reports/generate</code> with JSON body: <code>{"table":"orders","max_rows":5000}</code></p>`)
}

// allowedTables restricts which tables can be queried.
var allowedTables = map[string]bool{
	"orders": true, "invoices": true, "documents": true,
}

func serveReportGeneratorAPI(m *ResourceModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		Table   string `json:"table"`
		MaxRows int    `json:"max_rows"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if !allowedTables[body.Table] {
		jsonError(w, "invalid table", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// No limit — will return all rows
		var rows []map[string]any
		m.store.DB().Table(body.Table).Find(&rows)
		json.NewEncoder(w).Encode(map[string]any{"rows": rows, "count": len(rows)})

	case core.Medium:
		// Soft cap returned in response but not enforced
		var rows []map[string]any
		m.store.DB().Table(body.Table).Find(&rows)
		_ = body.MaxRows // advertised but ignored
		json.NewEncoder(w).Encode(map[string]any{
			"rows": rows, "count": len(rows),
			"note": fmt.Sprintf("requested max_rows=%d but ignored", body.MaxRows),
		})

	case core.Hard:
		// Enforced cap + timeout
		if body.MaxRows <= 0 || body.MaxRows > 1000 {
			body.MaxRows = 1000
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var rows []map[string]any
		if err := m.store.DB().WithContext(ctx).Table(body.Table).Limit(body.MaxRows).Find(&rows).Error; err != nil {
			jsonError(w, "query failed or timed out", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"rows": rows, "count": len(rows), "capped_at": body.MaxRows})
	}
}

// --- Notification Blast ---

// ipCounters and accountCounters are now instance fields on ResourceModule.
// See module.go for the field definitions.

func notificationBlastMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "notification-blast",
		Name:     "Notification Blast",
		Category: "Unrestricted Resource Consumption",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		},
		Hints: [4]string{
			"Send a notification via the API.",
			"Can you send many notifications quickly?",
			"Is the IP rate limit bypassable via a header?",
			"Hard mode uses per-account quota.",
		},
	}
}

func serveNotificationBlastInfo(m *ResourceModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Notification Blast</h3>
<p>POST to <code>/api/v1/notifications/send</code> with JSON body: <code>{"recipient":"user@example.com","body":"hello"}</code></p>`)
}

func serveNotificationBlastAPI(m *ResourceModule, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	sess := m.sess.Get(cookie.Value)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	var body struct {
		Recipient string `json:"recipient"`
		Body      string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.Recipient == "" || body.Body == "" {
		jsonError(w, "recipient and body required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// No rate limit
		n := database.Notification{
			SenderID:  uint(sess.UserID),
			Recipient: body.Recipient,
			Body:      body.Body,
		}
		m.store.DB().Create(&n)
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "id": n.ID})

	case core.Medium:
		// IP rate limit — bypassable via X-Forwarded-For
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
		m.IPMu.Lock()
		m.IPCounters[ip]++
		count := m.IPCounters[ip]
		m.IPMu.Unlock()
		if count > 10 {
			jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		n := database.Notification{SenderID: uint(sess.UserID), Recipient: body.Recipient, Body: body.Body}
		m.store.DB().Create(&n)
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "id": n.ID, "remaining": 10 - count})

	case core.Hard:
		// Per-account quota (max 5 per session lifetime)
		m.AccountMu.Lock()
		m.AccountCounters[sess.UserID]++
		count := m.AccountCounters[sess.UserID]
		m.AccountMu.Unlock()
		if count > 5 {
			jsonError(w, "quota exceeded — max 5 notifications per account", http.StatusTooManyRequests)
			return
		}
		n := database.Notification{SenderID: uint(sess.UserID), Recipient: body.Recipient, Body: body.Body}
		m.store.DB().Create(&n)
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "id": n.ID, "remaining": 5 - count})
	}
}
