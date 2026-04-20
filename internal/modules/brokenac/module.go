package brokenac

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BrokenACModule, w http.ResponseWriter, r *http.Request)

// BrokenACModule handles all Broken Access Control sub-scenarios via an
// injected scenario function. One struct covers idor, path-traversal, and privesc.
type BrokenACModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
	sess       *session.Manager
}

func (m *BrokenACModule) Meta() core.ModuleMeta { return m.meta }

func (m *BrokenACModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
