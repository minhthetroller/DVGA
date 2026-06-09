// Package components implements Vulnerable and Outdated Components scenarios.
package components

import (
	"net/http"

	"DVGA/internal/core"
)

type scenarioFunc func(m *ComponentsModule, w http.ResponseWriter, r *http.Request)

// ComponentsModule handles all vulnerable/outdated component sub-scenarios.
type ComponentsModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
}

func (m *ComponentsModule) Meta() core.ModuleMeta { return m.meta }

func (m *ComponentsModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
