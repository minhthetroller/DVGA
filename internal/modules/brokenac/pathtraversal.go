package brokenac

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"DVGA/internal/core"
)

const baseFilesDir = "./data/files"

func pathTraversalMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "path-traversal",
		Name:        "Document Library",
		Description: "View company documents.",
		Category:    "Broken Access Control",
		Difficulty:  d,
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

func servePathTraversal(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	if filename == "" {
		fmt.Fprint(w, ptRenderForm(""))
		return
	}
	switch m.difficulty {
	case core.Easy:
		ptEasy(w, filename)
	case core.Medium:
		ptMedium(w, filename)
	case core.Hard:
		ptHard(w, filename)
	}
}

func ptEasy(w http.ResponseWriter, filename string) {
	data, err := os.ReadFile(baseFilesDir + "/" + filename)
	if err != nil {
		fmt.Fprint(w, ptRenderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, ptRenderForm("<pre>"+string(data)+"</pre>"))
}

func ptMedium(w http.ResponseWriter, filename string) {
	sanitized := strings.ReplaceAll(filename, "../", "")
	data, err := os.ReadFile(baseFilesDir + "/" + sanitized)
	if err != nil {
		fmt.Fprint(w, ptRenderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, ptRenderForm("<pre>"+string(data)+"</pre>"))
}

func ptHard(w http.ResponseWriter, filename string) {
	absBase, _ := filepath.Abs(baseFilesDir)
	cleaned := filepath.Clean(filepath.Join(baseFilesDir, filename))
	absCleaned, _ := filepath.Abs(cleaned)
	if !strings.HasPrefix(absCleaned, absBase+string(os.PathSeparator)) {
		fmt.Fprint(w, ptRenderForm(`<div class="error">File not found.</div>`))
		return
	}
	data, err := os.ReadFile(absCleaned)
	if err != nil {
		fmt.Fprint(w, ptRenderForm(`<div class="error">File not found.</div>`))
		return
	}
	fmt.Fprint(w, ptRenderForm("<pre>"+string(data)+"</pre>"))
}

func ptRenderForm(output string) string {
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

