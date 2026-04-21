package misconfig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"DVGA/internal/core"
)

func securityHeadersMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "security-headers",
		Name:        "Security Check",
		Description: "Inspect your application security posture.",
		Category:    "Security Misconfiguration",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://securityheaders.com/",
		},
		Hints: [4]string{
			"Security isn't just about the body",
			"Inspect the HTTP response headers",
			"Missing headers = missing protections",
			"No CSP, no X-Frame-Options — try clickjacking or XSS",
		},
	}
}

func serveSecurityHeaders(m *MisconfigModule, w http.ResponseWriter, r *http.Request) {
	switch m.difficulty {
	case core.Easy:
		shApplyEasy(w)
	case core.Medium:
		shApplyMedium(w, r)
	case core.Hard:
		shApplyHard(w, r)
	}

	headerMap := make(map[string]string)
	for name, values := range w.Header() {
		if len(values) > 0 {
			headerMap[name] = values[0]
		}
	}

	type checkResult struct {
		Header string `json:"header"`
		Status string `json:"status"`
	}
	checks := []struct{ Name, Key string }{
		{"X-Frame-Options", "X-Frame-Options"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
		{"Content-Security-Policy", "Content-Security-Policy"},
		{"Strict-Transport-Security", "Strict-Transport-Security"},
		{"Referrer-Policy", "Referrer-Policy"},
		{"Access-Control-Allow-Origin", "Access-Control-Allow-Origin"},
	}
	var results []checkResult
	for _, c := range checks {
		val := w.Header().Get(c.Key)
		status := "missing"
		if val != "" {
			if c.Key == "Access-Control-Allow-Origin" && val == "*" {
				status = "permissive"
			} else {
				status = "present"
			}
		}
		results = append(results, checkResult{Header: c.Name, Status: status})
	}
	resp := map[string]any{"headers": headerMap, "audit": results}
	data, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Fprint(w, shRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func shApplyEasy(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}

func shApplyMedium(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	origin := r.Header.Get("Origin")
	if origin != "" && strings.Contains(origin, "example.com") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

func shApplyHard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Referrer-Policy", "no-referrer")
	origin := r.Header.Get("Origin")
	if origin == "http://localhost:4280" || origin == "http://127.0.0.1:4280" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

func shRenderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Security Check</h3>
<p>Inspect the security headers of this page.</p>
</div>`
	if output != "" {
		html += output
	}
	return html
}


