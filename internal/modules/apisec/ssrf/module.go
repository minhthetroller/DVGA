// Package ssrf implements Server-Side Request Forgery API vulnerability modules.
package ssrf

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *SSRFModule, w http.ResponseWriter, r *http.Request)

// SSRFModule handles Server-Side Request Forgery sub-scenarios.
type SSRFModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *SSRFModule) Meta() core.ModuleMeta          { return m.meta }
func (m *SSRFModule) APIRoutes() []core.APIRouteSpec { return m.apiRoutes }
func (m *SSRFModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serveInfo(m, w, r)
}
func (m *SSRFModule) ServeAPI(w http.ResponseWriter, r *http.Request) {
	m.serveAPI(m, w, r)
}
