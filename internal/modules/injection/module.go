// Package injection implements injection vulnerability scenarios (SQLi, CMDi, XSS).
package injection

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

type scenarioFunc func(m *InjectionModule, w http.ResponseWriter, r *http.Request)

// InjectionModule handles all Injection sub-scenarios via an injected scenario function.
type InjectionModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
}

func (m *InjectionModule) Meta() core.ModuleMeta { return m.meta }

func (m *InjectionModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
