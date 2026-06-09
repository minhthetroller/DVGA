package components

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"

	"DVGA/internal/core"
)

func legacyMarkdownMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "legacy-markdown",
		Name:        "Legacy Markdown Preview",
		Description: "Preview formatted release notes before publishing.",
		Category:    "Vulnerable and Outdated Components",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		},
		Hints: [4]string{
			"The previewer uses an old renderer.",
			"Does markdown input allow raw HTML?",
			"Removing only script tags leaves other HTML event handlers.",
			"Hard mode treats user-authored markup as text.",
		},
	}
}

var scriptBlockPattern = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)

func serveLegacyMarkdown(m *ComponentsModule, w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	if body == "" {
		fmt.Fprint(w, lmRenderForm("", ""))
		return
	}

	var rendered string
	switch m.difficulty {
	case core.Easy:
		rendered = lmRenderMarkdown(body)
	case core.Medium:
		rendered = lmRenderMarkdown(scriptBlockPattern.ReplaceAllString(body, ""))
	case core.Hard:
		rendered = lmRenderMarkdown(html.EscapeString(body))
	}

	fmt.Fprint(w, lmRenderForm(body, `<div class="output markdown-preview">`+rendered+`</div>`))
}

func lmRenderMarkdown(input string) string {
	rendered := strings.ReplaceAll(input, "\r\n", "\n")
	rendered = strings.ReplaceAll(rendered, "\n", "<br/>")
	strongPattern := regexp.MustCompile(`\*\*([^*]+)\*\*`)
	return strongPattern.ReplaceAllString(rendered, "<strong>$1</strong>")
}

func lmRenderForm(body, output string) string {
	htmlBody := html.EscapeString(body)
	page := `<div class="vuln-form">
<h3>Legacy Markdown Preview</h3>
<p>Preview release notes before publishing.</p>
<form method="POST">
<label>Markdown</label><br/>
<textarea name="body" rows="7" cols="80">` + htmlBody + `</textarea><br/>
<input type="submit" value="Preview" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page
}
