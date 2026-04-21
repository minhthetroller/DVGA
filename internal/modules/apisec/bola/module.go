// Package bola implements the Broken Object Level Authorization (BOLA) API vulnerability module.
package bola

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BOLAModule, w http.ResponseWriter, r *http.Request)

// BOLAModule handles BOLA (Broken Object Level Authorization) sub-scenarios.
type BOLAModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *BOLAModule) Meta() core.ModuleMeta              { return m.meta }
func (m *BOLAModule) APIRoutes() []core.APIRouteSpec     { return m.apiRoutes }
func (m *BOLAModule) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serveInfo(m, w, r) }
func (m *BOLAModule) ServeAPI(w http.ResponseWriter, r *http.Request)  { m.serveAPI(m, w, r) }
