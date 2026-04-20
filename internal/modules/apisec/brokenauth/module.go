package brokenauth

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BrokenAuthModule, w http.ResponseWriter, r *http.Request)

// BrokenAuthModule handles Broken Authentication sub-scenarios.
type BrokenAuthModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *BrokenAuthModule) Meta() core.ModuleMeta              { return m.meta }
func (m *BrokenAuthModule) APIRoutes() []core.APIRouteSpec     { return m.apiRoutes }
func (m *BrokenAuthModule) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serveInfo(m, w, r) }
func (m *BrokenAuthModule) ServeAPI(w http.ResponseWriter, r *http.Request)  { m.serveAPI(m, w, r) }
