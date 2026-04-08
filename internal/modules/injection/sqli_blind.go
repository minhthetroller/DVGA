package injection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type SQLiBlindFactory struct {
	store *database.Store
}

func (f *SQLiBlindFactory) Create(d core.Difficulty) core.VulnModule {
	return &SQLiBlindModule{difficulty: d, store: f.store}
}

// --- Module ---

type SQLiBlindModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *SQLiBlindModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "sqli-blind",
		Name:        "Username Availability",
		Description: "Check if a username is available for registration.",
		Category:    "Injection",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
		},
		Hints: [4]string{
			"Not all truths are visible in the response",
			"Timing can reveal secrets the page hides",
			"Compare response times for true vs false conditions",
			"Use sleep-based payloads to exfiltrate data bit by bit",
		},
	}
}

func (m *SQLiBlindModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("username")
	if input == "" {
		fmt.Fprint(w, m.renderForm(""))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, input)
	case core.Medium:
		m.serveMedium(w, input)
	case core.Hard:
		m.serveHard(w, input)
	}
}

func (m *SQLiBlindModule) serveEasy(w http.ResponseWriter, input string) {
	// VULNERABLE: direct concatenation — boolean blind + time-based blind
	query := "SELECT 1 FROM users WHERE username = '" + input + "' LIMIT 1"
	var result int
	err := m.store.DB().Raw(query).Scan(&result).Error

	resp := map[string]bool{"available": true}
	if err == nil && result == 1 {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *SQLiBlindModule) serveMedium(w http.ResponseWriter, input string) {
	// PARTIALLY VULNERABLE: escapes single quotes but allows other injection
	escaped := strings.ReplaceAll(input, "'", "\\'")
	query := "SELECT 1 FROM users WHERE username = '" + escaped + "' LIMIT 1"
	var result int
	err := m.store.DB().Raw(query).Scan(&result).Error

	resp := map[string]bool{"available": true}
	if err == nil && result == 1 {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *SQLiBlindModule) serveHard(w http.ResponseWriter, input string) {
	// SECURE: parameterized query
	var user database.User
	err := m.store.DB().Where("username = ?", input).First(&user).Error

	resp := map[string]bool{"available": true}
	if err == nil {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *SQLiBlindModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Check Username Availability</h3>
<p>Enter a username to check if it's available for registration:</p>
<form method="GET">
<label>Username: <input type="text" name="username" /></label>
<input type="submit" value="Check" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
