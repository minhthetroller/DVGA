package componentstest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

func TestComponentsRegisteredUnderExpectedCategory(t *testing.T) {
	app := newTestApp(t)
	cats := app.registry.Categories(core.Easy)

	var ids []string
	for _, mod := range cats["Vulnerable and Outdated Components"] {
		ids = append(ids, mod.Meta().ID)
	}

	assert.ElementsMatch(t, []string{"component-inventory", "legacy-markdown"}, ids)
}

func TestComponentInventoryByDifficulty(t *testing.T) {
	app := newTestApp(t)

	w := doModuleRequest(t, app, "component-inventory", http.MethodGet, "/", nil)
	body := w.Body.String()
	assert.Contains(t, body, "CVE-2021-44228")
	assert.Contains(t, body, "internal_path")

	app.setDifficulty(core.Medium)
	w = doModuleRequest(t, app, "component-inventory", http.MethodGet, "/", nil)
	body = w.Body.String()
	assert.Contains(t, body, "2.14.x")
	assert.NotContains(t, body, "CVE-2021-44228")

	app.setDifficulty(core.Hard)
	w = doModuleRequest(t, app, "component-inventory", http.MethodGet, "/", nil)
	body = w.Body.String()
	assert.Contains(t, body, "supported")
	assert.NotContains(t, body, "2.14.1")
	assert.NotContains(t, body, "internal_path")
}

func TestLegacyMarkdownByDifficulty(t *testing.T) {
	app := newTestApp(t)
	payload := `<img src=x onerror=alert(1)><script>alert(2)</script>`

	w := doModuleRequest(t, app, "legacy-markdown", http.MethodPost, "/", formBody("body", payload))
	body := w.Body.String()
	assert.Contains(t, body, `<img src=x onerror=alert(1)>`)
	assert.Contains(t, body, `<script>alert(2)</script>`)

	app.setDifficulty(core.Medium)
	w = doModuleRequest(t, app, "legacy-markdown", http.MethodPost, "/", formBody("body", payload))
	body = w.Body.String()
	assert.Contains(t, body, `<img src=x onerror=alert(1)>`)
	assert.NotContains(t, body, `<script>alert(2)</script>`)

	app.setDifficulty(core.Hard)
	w = doModuleRequest(t, app, "legacy-markdown", http.MethodPost, "/", formBody("body", payload))
	body = w.Body.String()
	assert.Contains(t, body, `&lt;img src=x onerror=alert(1)&gt;`)
	assert.NotContains(t, body, `<img src=x onerror=alert(1)>`)
	assert.NotContains(t, body, `<script>alert(2)</script>`)
}
