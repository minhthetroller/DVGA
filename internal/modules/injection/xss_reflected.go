package injection

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type XSSReflectedFactory struct {
	store *database.Store
}

func (f *XSSReflectedFactory) Create(d core.Difficulty) core.VulnModule {
	return &XSSReflectedModule{difficulty: d, store: f.store}
}

// --- Module ---

type XSSReflectedModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *XSSReflectedModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "xss-reflected",
		Name:        "Product Search",
		Description: "Search our product catalog.",
		Category:    "Injection",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://owasp.org/www-community/attacks/xss/",
		},
		Hints: [4]string{
			"What you send comes back",
			"The search term appears in the page",
			"HTML tags might not be filtered",
			"<img src=x onerror=alert(1)>",
		},
	}
}

func (m *XSSReflectedModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("q")
	if search == "" {
		fmt.Fprint(w, m.renderForm("", ""))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, search)
	case core.Medium:
		m.serveMedium(w, search)
	case core.Hard:
		m.serveHard(w, search)
	}
}

func (m *XSSReflectedModule) serveEasy(w http.ResponseWriter, search string) {
	// VULNERABLE: search term reflected without any escaping
	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)

	output := "<p>Results for: " + search + "</p>"
	output += m.formatResults(users)
	fmt.Fprint(w, m.renderForm("", output))
}

func (m *XSSReflectedModule) serveMedium(w http.ResponseWriter, search string) {
	// PARTIALLY VULNERABLE: strips <script> tags but not other vectors
	sanitized := strings.ReplaceAll(search, "<script>", "")
	sanitized = strings.ReplaceAll(sanitized, "</script>", "")

	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)

	output := "<p>Results for: " + sanitized + "</p>"
	output += m.formatResults(users)
	fmt.Fprint(w, m.renderForm("", output))
}

func (m *XSSReflectedModule) serveHard(w http.ResponseWriter, search string) {
	// SECURE: HTML-escaped output + CSP header
	w.Header().Set("Content-Security-Policy", "script-src 'self'")

	escaped := template.HTMLEscapeString(search)
	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)

	output := "<p>Results for: " + escaped + "</p>"
	output += m.formatResults(users)
	fmt.Fprint(w, m.renderForm("", output))
}

func (m *XSSReflectedModule) formatResults(users []database.User) string {
	if len(users) == 0 {
		return "<p>No results found.</p>"
	}
	result := "<ul>"
	for _, u := range users {
		result += fmt.Sprintf("<li>%s — %s</li>", template.HTMLEscapeString(u.Username), template.HTMLEscapeString(u.Role))
	}
	result += "</ul>"
	return result
}

func (m *XSSReflectedModule) renderForm(errMsg, output string) string {
	html := `<div class="vuln-form">
<h3>Product Search</h3>
<form method="GET">
<label>Search: <input type="text" name="q" placeholder="Search products..." /></label>
<input type="submit" value="Search" />
</form>
</div>`
	if errMsg != "" {
		html += `<div class="error">` + errMsg + `</div>`
	}
	if output != "" {
		html += `<div class="output">` + output + `</div>`
	}
	return html
}
