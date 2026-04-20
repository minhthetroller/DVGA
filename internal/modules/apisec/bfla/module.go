package bfla

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BFLAModule, w http.ResponseWriter, r *http.Request)

// BFLAModule handles Broken Function Level Authorization sub-scenarios.
type BFLAModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *BFLAModule) Meta() core.ModuleMeta              { return m.meta }
func (m *BFLAModule) APIRoutes() []core.APIRouteSpec     { return m.apiRoutes }
func (m *BFLAModule) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serveInfo(m, w, r) }
func (m *BFLAModule) ServeAPI(w http.ResponseWriter, r *http.Request)  { m.serveAPI(m, w, r) }
