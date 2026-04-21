package injection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func sqliBlindMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "sqli-blind",
		Name:        "Username Availability",
		Description: "Check if a username is available for registration.",
		Category:    "Injection",
		Difficulty:  d,
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

func serveSQLiBlind(m *InjectionModule, w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("username")
	if input == "" {
		fmt.Fprint(w, sqliBlindRenderForm(""))
		return
	}
	switch m.difficulty {
	case core.Easy:
		sqliBlindEasy(m, w, input)
	case core.Medium:
		sqliBlindMedium(m, w, input)
	case core.Hard:
		sqliBlindHard(m, w, input)
	}
}

func sqliBlindEasy(m *InjectionModule, w http.ResponseWriter, input string) {
	query := "SELECT 1 FROM users WHERE username = '" + input + "' LIMIT 1"
	var result int
	err := m.store.DB().Raw(query).Scan(&result).Error
	resp := map[string]bool{"available": true}
	if err == nil && result == 1 {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, sqliBlindRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func sqliBlindMedium(m *InjectionModule, w http.ResponseWriter, input string) {
	escaped := strings.ReplaceAll(input, "'", "\\'")
	query := "SELECT 1 FROM users WHERE username = '" + escaped + "' LIMIT 1"
	var result int
	err := m.store.DB().Raw(query).Scan(&result).Error
	resp := map[string]bool{"available": true}
	if err == nil && result == 1 {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, sqliBlindRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func sqliBlindHard(m *InjectionModule, w http.ResponseWriter, input string) {
	var user database.User
	err := m.store.DB().Where("username = ?", input).First(&user).Error
	resp := map[string]bool{"available": true}
	if err == nil {
		resp["available"] = false
	}
	data, _ := json.Marshal(resp)
	fmt.Fprint(w, sqliBlindRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func sqliBlindRenderForm(output string) string {
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


