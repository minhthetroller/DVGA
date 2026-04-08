package misconfig

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type DebugInfoFactory struct {
	store *database.Store
}

func (f *DebugInfoFactory) Create(d core.Difficulty) core.VulnModule {
	return &DebugInfoModule{difficulty: d, store: f.store}
}

// --- Module ---

type DebugInfoModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *DebugInfoModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "debug-info",
		Name:        "Debug Info",
		Description: "Verbose error messages and debug endpoints that leak server internals.",
		Category:    "Security Misconfiguration",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
		},
	}
}

func (m *DebugInfoModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, action)
	case core.Medium:
		m.serveMedium(w, action)
	case core.Hard:
		m.serveHard(w, action)
	}
}

func (m *DebugInfoModule) serveEasy(w http.ResponseWriter, action string) {
	// VULNERABLE: full info leakage
	w.Header().Set("Server", "Go/"+runtime.Version())

	output := "<h3>Server Information</h3>"
	output += fmt.Sprintf("<table class='result-table'>"+
		"<tr><td><b>Go Version</b></td><td>%s</td></tr>"+
		"<tr><td><b>OS/Arch</b></td><td>%s/%s</td></tr>"+
		"<tr><td><b>NumCPU</b></td><td>%d</td></tr>"+
		"<tr><td><b>NumGoroutine</b></td><td>%d</td></tr>"+
		"</table>",
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
		runtime.NumCPU(), runtime.NumGoroutine())

	// Show environment variables
	output += "<h4>Environment Variables</h4><pre>"
	for _, env := range os.Environ() {
		output += env + "\n"
	}
	output += "</pre>"

	if action == "error" {
		// Trigger an error and show full stack trace
		output += "<h4>Triggered Error — Stack Trace</h4><pre>"
		output += string(debug.Stack())
		output += "</pre>"

		// Also show a DB error
		var result interface{}
		err := m.store.DB().Raw("SELECT * FROM nonexistent_table").Scan(&result).Error
		if err != nil {
			output += "<h4>Database Error</h4><pre>" + err.Error() + "</pre>"
		}
	}

	fmt.Fprint(w, m.renderForm("", output))
}

func (m *DebugInfoModule) serveMedium(w http.ResponseWriter, action string) {
	// PARTIALLY VULNERABLE: no stack traces but descriptive errors
	output := "<h3>Server Information</h3>"
	output += fmt.Sprintf("<table class='result-table'>"+
		"<tr><td><b>Go Version</b></td><td>%s</td></tr>"+
		"<tr><td><b>OS/Arch</b></td><td>%s/%s</td></tr>"+
		"</table>",
		runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if action == "error" {
		var result interface{}
		err := m.store.DB().Raw("SELECT * FROM nonexistent_table").Scan(&result).Error
		if err != nil {
			output += "<h4>Error</h4><p>" + err.Error() + "</p>"
		}
	}

	fmt.Fprint(w, m.renderForm("", output))
}

func (m *DebugInfoModule) serveHard(w http.ResponseWriter, action string) {
	// SECURE: generic errors, no info leakage
	output := "<h3>Server Information</h3>"
	output += "<p>Server is running.</p>"

	if action == "error" {
		output += "<h4>Error</h4><p>An error occurred. Please contact the administrator.</p>"
	}

	fmt.Fprint(w, m.renderForm("", output))
}

func (m *DebugInfoModule) renderForm(errMsg, output string) string {
	html := `<h2>Vulnerability: Debug Info</h2>
<div class="vuln-form">
<h3>Error Test</h3>
<p>Click below to trigger a server error and see what information is revealed:</p>
<form method="GET">
<input type="hidden" name="action" value="error" />
<input type="submit" value="Trigger Error" />
</form>
<form method="GET">
<input type="submit" value="Show Server Info" />
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
