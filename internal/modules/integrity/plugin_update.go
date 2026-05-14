package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	"DVGA/internal/core"
)

func pluginUpdateMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "plugin-update",
		Name:        "Plugin Update Center",
		Description: "Import plugin update metadata for deployment.",
		Category:    "Software and Data Integrity Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
		},
		Hints: [4]string{
			"Updates need provenance, not just metadata.",
			"Who controls the URL and version fields?",
			"A checksum supplied by the same manifest is not a trust boundary.",
			"Hard mode compares updates against a server-side allowlist.",
		},
	}
}

type pluginManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

var approvedPlugin = pluginManifest{
	Name:    "calendar-sync",
	Version: "1.4.2",
	URL:     "https://updates.dvga.local/plugins/calendar-sync-1.4.2.zip",
	SHA256:  "c78277c7e015f87ae351d7970037554ffd1503e03c209f465907224af9ea4122",
}

func servePluginUpdate(m *IntegrityModule, w http.ResponseWriter, r *http.Request) {
	manifestText := r.FormValue("manifest")
	if manifestText == "" {
		fmt.Fprint(w, puRenderForm(defaultPluginManifest(), ""))
		return
	}

	var manifest pluginManifest
	if err := json.Unmarshal([]byte(manifestText), &manifest); err != nil {
		fmt.Fprint(w, puRenderForm(manifestText, `<div class="error">Invalid manifest JSON.</div>`))
		return
	}

	switch m.difficulty {
	case core.Easy:
		puRenderResult(w, manifestText, map[string]any{
			"accepted": true,
			"name":     manifest.Name,
			"version":  manifest.Version,
			"source":   manifest.URL,
			"note":     "update trusted without integrity verification",
		})
	case core.Medium:
		if manifest.SHA256 == "" {
			fmt.Fprint(w, puRenderForm(manifestText, `<div class="error">Checksum required.</div>`))
			return
		}
		expected := simulatedPluginPayloadHash(manifest.URL)
		accepted := manifest.SHA256 == expected
		status := map[string]any{
			"accepted":          accepted,
			"name":              manifest.Name,
			"version":           manifest.Version,
			"attacker_checksum": manifest.SHA256,
			"computed_checksum": expected,
			"note":              "checksum is supplied by the same untrusted manifest",
		}
		puRenderResult(w, manifestText, status)
	case core.Hard:
		accepted := manifest == approvedPlugin
		status := map[string]any{
			"accepted": accepted,
			"name":     manifest.Name,
			"version":  manifest.Version,
			"note":     "server-side allowlist and pinned checksum required",
		}
		if !accepted {
			status["error"] = "update source is not trusted"
		}
		puRenderResult(w, manifestText, status)
	}
}

func simulatedPluginPayloadHash(url string) string {
	sum := sha256.Sum256([]byte("payload from " + url))
	return hex.EncodeToString(sum[:])
}

func defaultPluginManifest() string {
	data, _ := json.MarshalIndent(approvedPlugin, "", "  ")
	return string(data)
}

func puRenderResult(w http.ResponseWriter, manifestText string, result map[string]any) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprint(w, puRenderForm(manifestText, `<pre class="output">`+string(data)+`</pre>`))
}

func puRenderForm(manifestText, output string) string {
	page := `<div class="vuln-form">
<h3>Plugin Update Center</h3>
<p>Paste plugin update metadata to stage an update.</p>
<form method="POST">
<label>Manifest JSON</label><br/>
<textarea name="manifest" rows="9" cols="90">` + html.EscapeString(manifestText) + `</textarea><br/>
<input type="submit" value="Import Update" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page
}
