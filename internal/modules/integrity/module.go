// Package integrity implements Software and Data Integrity Failures scenarios.
package integrity

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/session"
)

type scenarioFunc func(m *IntegrityModule, w http.ResponseWriter, r *http.Request)

// IntegrityModule handles all software/data integrity scenarios.
type IntegrityModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	sess       *session.Manager
}

func (m *IntegrityModule) Meta() core.ModuleMeta { return m.meta }

func (m *IntegrityModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
