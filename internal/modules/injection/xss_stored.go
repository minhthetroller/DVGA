package injection

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type XSSStoredFactory struct {
	store *database.Store
}

func (f *XSSStoredFactory) Create(d core.Difficulty) core.VulnModule {
	return &XSSStoredModule{difficulty: d, store: f.store}
}

// --- Module ---

type XSSStoredModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *XSSStoredModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "xss-stored",
		Name:        "Customer Reviews",
		Description: "Read and write product reviews.",
		Category:    "Injection",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://owasp.org/www-community/attacks/xss/",
		},
		Hints: [4]string{
			"Your words are remembered",
			"Other users see exactly what you wrote",
			"Does the app sanitize before storing or rendering?",
			"Store a <script> tag or <img onerror=...> in the review body",
		},
	}
}

func (m *XSSStoredModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		m.handlePost(w, r)
		return
	}
	m.serveList(w)
}

func (m *XSSStoredModule) handlePost(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	body := r.FormValue("review")
	if name == "" || body == "" {
		fmt.Fprint(w, m.renderForm("Name and review are required.", ""))
		return
	}

	var storedBody string
	switch m.difficulty {
	case core.Easy:
		storedBody = body
	case core.Medium:
		storedBody = strings.ReplaceAll(body, "<script>", "")
		storedBody = strings.ReplaceAll(storedBody, "</script>", "")
		storedBody = strings.ReplaceAll(storedBody, "<SCRIPT>", "")
		storedBody = strings.ReplaceAll(storedBody, "</SCRIPT>", "")
	case core.Hard:
		storedBody = body
	}

	m.store.DB().Create(&database.Comment{
		Username:  name,
		Body:      storedBody,
		CreatedAt: time.Now(),
	})
	m.serveList(w)
}

func (m *XSSStoredModule) serveList(w http.ResponseWriter) {
	var comments []database.Comment
	m.store.DB().Order("created_at desc").Find(&comments)

	output := ""
	if len(comments) == 0 {
		output += "<p>No reviews yet. Be the first to leave one!</p>"
	} else {
		for _, c := range comments {
			var body string
			switch m.difficulty {
			case core.Easy:
				body = c.Body
			case core.Medium:
				body = c.Body
			case core.Hard:
				body = template.HTMLEscapeString(c.Body)
				w.Header().Set("Content-Security-Policy", "script-src 'self'")
			}
			output += fmt.Sprintf(`<div class="comment" style="border:1px solid #ddd;padding:0.75rem;margin-bottom:0.5rem;border-radius:4px">
<p><strong>%s</strong> <small style="color:#888">%s</small></p>
<p>%s</p>
</div>`, template.HTMLEscapeString(c.Username), c.CreatedAt.Format("Jan 2, 2006 3:04 PM"), body)
		}
	}
	fmt.Fprint(w, m.renderForm("", output))
}

func (m *XSSStoredModule) renderForm(errMsg, output string) string {
	html := `<div class="vuln-form">
<h3>Customer Reviews</h3>
<form method="POST">
<label>Your Name: <input type="text" name="name" /></label><br/>
<label>Review:<br/><textarea name="review" rows="3" cols="40" placeholder="Write your review..."></textarea></label><br/>
<input type="submit" value="Submit Review" />
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
