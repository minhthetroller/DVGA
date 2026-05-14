package securitymisconfig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

func currentSession(m *SecurityMisconfigModule, r *http.Request) *session.Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	return m.sess.Get(cookie.Value)
}

func debugConfigMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "debug-config",
		Name:       "Debug Config",
		Category:   "Security Misconfiguration",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		Hints: [4]string{
			"Request the system debug endpoint.",
			"What configuration values are exposed?",
			"Can a header enable debug mode?",
			"Hard mode requires admin and redacts secrets.",
		},
	}
}

func serveDebugConfigInfo(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Debug Config</h3>
<p>GET <code>/api/v1/system/debug</code> to inspect runtime diagnostics.</p>`)
}

func serveDebugConfigAPI(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(debugPayload(m.store, false))
	case core.Medium:
		if strings.ToLower(r.Header.Get("X-Debug")) != "true" {
			json.NewEncoder(w).Encode(map[string]any{"status": "debug disabled"})
			return
		}
		json.NewEncoder(w).Encode(debugPayload(m.store, false))
	case core.Hard:
		sess := currentSession(m, r)
		if sess == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if sess.Role != "admin" {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(debugPayload(m.store, true))
	}
}

func debugPayload(store *database.Store, redacted bool) map[string]any {
	var secret database.Secret
	store.DB().First(&secret)
	secretValue := secret.Value
	adminPassword := "admin"
	if redacted {
		secretValue = "[redacted]"
		adminPassword = "[redacted]"
	}
	return map[string]any{
		"database_url":   "sqlite://dvga.db",
		"environment":    "development",
		"admin_password": adminPassword,
		"sample_secret":  secretValue,
	}
}

func corsPolicyMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "cors-policy",
		Name:       "CORS Policy",
		Category:   "Security Misconfiguration",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		Hints: [4]string{
			"Send an Origin header to the CORS endpoint.",
			"Does the server reflect arbitrary origins?",
			"Can a weak suffix check be bypassed?",
			"Hard mode uses an exact origin allowlist.",
		},
	}
}

func serveCorsPolicyInfo(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>CORS Policy</h3>
<p>GET <code>/api/v1/misconfig/cors</code> with an <code>Origin</code> header.</p>`)
}

func serveCorsPolicyAPI(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	w.Header().Set("Content-Type", "application/json")
	switch m.difficulty {
	case core.Easy:
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	case core.Medium:
		if weakTrustedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	case core.Hard:
		if exactTrustedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "origin": origin})
}

func weakTrustedOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, "corp.local")
}

func exactTrustedOrigin(origin string) bool {
	switch origin {
	case "https://app.corp.local", "https://admin.corp.local":
		return true
	default:
		return false
	}
}

func verboseErrorsMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "verbose-errors",
		Name:       "Verbose Errors",
		Category:   "Security Misconfiguration",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		},
		Hints: [4]string{
			"Query table metadata through the API.",
			"What happens with a table that does not exist?",
			"Try adding debug=true.",
			"Hard mode returns generic errors.",
		},
	}
}

func serveVerboseErrorsInfo(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Verbose Errors</h3>
<p>GET <code>/api/v1/system/query?table=orders</code> to query table metadata.</p>`)
}

func serveVerboseErrorsAPI(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request) {
	table := strings.TrimSpace(r.URL.Query().Get("table"))
	if table == "" {
		jsonError(w, "table required", http.StatusBadRequest)
		return
	}
	var count int64
	err := m.store.DB().Table(table).Count(&count).Error
	w.Header().Set("Content-Type", "application/json")
	if err == nil {
		json.NewEncoder(w).Encode(map[string]any{"table": table, "count": count})
		return
	}

	switch m.difficulty {
	case core.Easy:
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "table": table})
	case core.Medium:
		w.WriteHeader(http.StatusInternalServerError)
		if r.URL.Query().Get("debug") == "true" {
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "table": table})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"error": "query failed"})
	case core.Hard:
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": "query failed"})
	}
}
