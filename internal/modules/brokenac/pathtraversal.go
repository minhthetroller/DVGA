package brokenac

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"DVGA/internal/core"
)

// --- Factory ---

type PathTraversalFactory struct{}

func (f *PathTraversalFactory) Create(d core.Difficulty) core.VulnModule {
	return &PathTraversalModule{difficulty: d}
}

// --- Module ---

type PathTraversalModule struct {
	difficulty core.Difficulty
}

const baseFilesDir = "./data/files"

func (m *PathTraversalModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "path-traversal",
		Name:        "Document Library",
		Description: "View company documents.",
		Category:    "Broken Access Control",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/www-community/attacks/Path_Traversal",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Hints: [4]string{
			"Files live in directories",
			"What constrains which files you can access?",
			"Try navigating outside the intended directory",
			"Use ../../etc/passwd in the filename parameter",
		},
	}
}

func (m *PathTraversalModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	if filename == "" {
		fmt.Fprint(w, m.renderForm(""))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, filename)
	case core.Medium:
		m.serveMedium(w, filename)
	case core.Hard:
		m.serveHard(w, filename)
	}
}

func (m *PathTraversalModule) serveEasy(w http.ResponseWriter, filename string) {
	// VULNERABLE: no sanitization at all
	path := baseFilesDir + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(data)+"</pre>"))
}

func (m *PathTraversalModule) serveMedium(w http.ResponseWriter, filename string) {
	// PARTIALLY VULNERABLE: strips ../ once
	sanitized := strings.ReplaceAll(filename, "../", "")
	path := baseFilesDir + "/" + sanitized
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(data)+"</pre>"))
}

func (m *PathTraversalModule) serveHard(w http.ResponseWriter, filename string) {
	// SECURE: filepath.Clean + verify within base directory
	absBase, _ := filepath.Abs(baseFilesDir)
	cleaned := filepath.Clean(filepath.Join(baseFilesDir, filename))
	absCleaned, _ := filepath.Abs(cleaned)

	if !strings.HasPrefix(absCleaned, absBase+string(os.PathSeparator)) {
		fmt.Fprint(w, m.renderForm(`<div class="error">File not found.</div>`))
		return
	}
	data, err := os.ReadFile(absCleaned)
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(data)+"</pre>"))
}

func (m *PathTraversalModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Document Library</h3>
<p>Select a document to view:</p>
<form method="GET">
<label>Document: 
<select name="file">
<option value="">-- select --</option>
<option value="readme.txt">Company Readme</option>
<option value="config.txt">Configuration Guide</option>
<option value="notes.txt">Release Notes</option>
</select>
</label>
<input type="submit" value="View" />
</form>
<p style="margin-top:0.5rem"><small>Or enter a filename directly:</small></p>
<form method="GET">
<label>Filename: <input type="text" name="file" /></label>
<input type="submit" value="View" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
