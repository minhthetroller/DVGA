// Package misconfig implements Security Misconfiguration vulnerability scenarios.
package misconfig

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

type scenarioFunc func(m *MisconfigModule, w http.ResponseWriter, r *http.Request)

// MisconfigModule handles all Security Misconfiguration sub-scenarios.
type MisconfigModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
}

func (m *MisconfigModule) Meta() core.ModuleMeta { return m.meta }

func (m *MisconfigModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
