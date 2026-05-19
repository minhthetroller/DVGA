package components

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DVGA/internal/core"
)

func componentInventoryMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "component-inventory",
		Name:        "Component Inventory",
		Description: "Review application component versions and support status.",
		Category:    "Vulnerable and Outdated Components",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		},
		Hints: [4]string{
			"Inventory pages often reveal exact dependency versions.",
			"Search exposed versions for public CVEs.",
			"Partial masking still leaves enough fingerprinting data.",
			"Hard mode publishes only supported status, not exploitable versions.",
		},
	}
}

type componentRecord struct {
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Status        string `json:"status"`
	CVE           string `json:"cve,omitempty"`
	InternalPath  string `json:"internal_path,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
}

var vulnerableComponents = []componentRecord{
	{Name: "legacy-markdown", Version: "0.3.1", Status: "vulnerable", CVE: "CVE-2021-3918", InternalPath: "/opt/dvga/vendor/legacy-markdown"},
	{Name: "jquery", Version: "1.12.4", Status: "end-of-life", CVE: "CVE-2020-11023", InternalPath: "/static/vendor/jquery-1.12.4.js"},
	{Name: "log4j-core", Version: "2.14.1", Status: "vulnerable", CVE: "CVE-2021-44228", InternalPath: "/srv/reports/plugins/log4j-core-2.14.1.jar"},
}

func serveComponentInventory(m *ComponentsModule, w http.ResponseWriter, r *http.Request) {
	switch m.difficulty {
	case core.Easy:
		ciRender(w, vulnerableComponents, "Full dependency scan results.")
	case core.Medium:
		records := []componentRecord{
			{Name: "legacy-markdown", Version: "0.3.x", Status: "review required", LatestVersion: "1.8.0"},
			{Name: "jquery", Version: "1.x", Status: "review required", LatestVersion: "3.7.1"},
			{Name: "log4j-core", Version: "2.14.x", Status: "review required", LatestVersion: "2.23.1"},
		}
		ciRender(w, records, "Public CVE IDs are hidden, but component fingerprints remain.")
	case core.Hard:
		records := []componentRecord{
			{Name: "markdown renderer", Status: "supported"},
			{Name: "frontend library", Status: "supported"},
			{Name: "logging framework", Status: "not used in this deployment"},
		}
		ciRender(w, records, "Only supported component status is exposed.")
	}
}

func ciRender(w http.ResponseWriter, records []componentRecord, note string) {
	data, _ := json.MarshalIndent(map[string]any{
		"note":       note,
		"components": records,
	}, "", "  ")
	fmt.Fprint(w, `<div class="vuln-form">
<h3>Component Inventory</h3>
<p>Review third-party components detected in the deployment.</p>
</div>`)
	fmt.Fprint(w, `<pre class="output">`+string(data)+`</pre>`)
}
