// Package securitymisconfig implements Security Misconfiguration API vulnerability modules.
package securitymisconfig

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *SecurityMisconfigModule, w http.ResponseWriter, r *http.Request)

// SecurityMisconfigModule handles Security Misconfiguration sub-scenarios.
type SecurityMisconfigModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *SecurityMisconfigModule) Meta() core.ModuleMeta          { return m.meta }
func (m *SecurityMisconfigModule) APIRoutes() []core.APIRouteSpec { return m.apiRoutes }
func (m *SecurityMisconfigModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serveInfo(m, w, r)
}
func (m *SecurityMisconfigModule) ServeAPI(w http.ResponseWriter, r *http.Request) {
	m.serveAPI(m, w, r)
}
