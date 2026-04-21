package difficultytest

import (
	"net/http"
	"testing"


	"github.com/stretchr/testify/assert"
)

// TestAllModulesAtAllDifficulties verifies every registered module can be built at
// each difficulty and responds with HTTP 200 (no panics or crashes).
func TestAllModulesAtAllDifficulties(t *testing.T) {
	for _, d := range allDifficulties() {
		d := d // capture
		t.Run(d.String(), func(t *testing.T) {
			app := newTestApp(t)
			app.setDifficulty(d)

			token := app.mustLogin(adminUsername, adminPassword)
			cookie := app.sessionCookie(token)

			for _, id := range app.registry.IDs() {
				id := id // capture
				t.Run(id, func(t *testing.T) {
					w := doModuleRequest(t, app, id, http.MethodGet, "/", nil, cookie)
					// Module should respond — not panic (200 or redirect/error is fine)
					assert.NotNil(t, w)
					// 500 indicates a server panic/crash — that's always wrong
					assert.NotEqual(t, http.StatusInternalServerError, w.Code,
						"module %s at difficulty %s returned 500", id, d.String())
				})
			}
		})
	}
}

// TestModuleMetaDifficulty verifies every module's Meta().Difficulty matches
// the difficulty it was built at.
func TestModuleMetaDifficulty(t *testing.T) {
	for _, d := range allDifficulties() {
		d := d
		t.Run(d.String(), func(t *testing.T) {
			app := newTestApp(t)
			app.setDifficulty(d)

			for _, id := range app.registry.IDs() {
				id := id
				t.Run(id, func(t *testing.T) {
					mod := app.buildModule(id)
					meta := mod.Meta()
					assert.Equal(t, d, meta.Difficulty,
						"module %s built at %s but Meta().Difficulty=%s", id, d.String(), meta.Difficulty.String())
				})
			}
		})
	}
}
