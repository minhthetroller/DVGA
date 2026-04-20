package insecuredesign

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request)

// InsecureDesignModule handles all Insecure Design sub-scenarios.
type InsecureDesignModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
	sess       *session.Manager
}

func (m *InsecureDesignModule) Meta() core.ModuleMeta { return m.meta }

func (m *InsecureDesignModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
