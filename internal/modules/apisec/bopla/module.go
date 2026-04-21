// Package bopla implements the Broken Object Property Level Authorization (BOPLA) API vulnerability module.
package bopla

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BOPLAModule, w http.ResponseWriter, r *http.Request)

// BOPLAModule handles Broken Object Property Level Authorization sub-scenarios.
type BOPLAModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *BOPLAModule) Meta() core.ModuleMeta              { return m.meta }
func (m *BOPLAModule) APIRoutes() []core.APIRouteSpec     { return m.apiRoutes }
func (m *BOPLAModule) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serveInfo(m, w, r) }
func (m *BOPLAModule) ServeAPI(w http.ResponseWriter, r *http.Request)  { m.serveAPI(m, w, r) }
