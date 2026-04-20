package injection

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func xssReflectedMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "xss-reflected",
		Name:        "Product Search",
		Description: "Search our product catalog.",
		Category:    "Injection",
		Difficulty:  d,
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

func serveXSSReflected(m *InjectionModule, w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("q")
	if search == "" {
		fmt.Fprint(w, xssRenderForm("", ""))
		return
	}
	switch m.difficulty {
	case core.Easy:
		xssRefEasy(m, w, search)
	case core.Medium:
		xssRefMedium(m, w, search)
	case core.Hard:
		xssRefHard(m, w, search)
	}
}

func xssRefEasy(m *InjectionModule, w http.ResponseWriter, search string) {
	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)
	output := "<p>Results for: " + search + "</p>" + xssFormatResults(users)
	fmt.Fprint(w, xssRenderForm("", output))
}

func xssRefMedium(m *InjectionModule, w http.ResponseWriter, search string) {
	sanitized := strings.ReplaceAll(search, "<script>", "")
	sanitized = strings.ReplaceAll(sanitized, "</script>", "")
	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)
	output := "<p>Results for: " + sanitized + "</p>" + xssFormatResults(users)
	fmt.Fprint(w, xssRenderForm("", output))
}

func xssRefHard(m *InjectionModule, w http.ResponseWriter, search string) {
	w.Header().Set("Content-Security-Policy", "script-src 'self'")
	escaped := template.HTMLEscapeString(search)
	var users []database.User
	m.store.DB().Where("username LIKE ?", "%"+search+"%").Find(&users)
	output := "<p>Results for: " + escaped + "</p>" + xssFormatResults(users)
	fmt.Fprint(w, xssRenderForm("", output))
}

func xssFormatResults(users []database.User) string {
	if len(users) == 0 {
		return "<p>No results found.</p>"
	}
	result := "<ul>"
	for _, u := range users {
		result += fmt.Sprintf("<li>%s — %s</li>",
			template.HTMLEscapeString(u.Username),
			template.HTMLEscapeString(u.Role))
	}
	result += "</ul>"
	return result
}

func xssRenderForm(errMsg, output string) string {
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


