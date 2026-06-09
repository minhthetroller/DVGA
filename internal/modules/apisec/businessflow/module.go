// Package businessflow implements Unrestricted Access to Sensitive Business Flows API vulnerability modules.
package businessflow

import (
	"net/http"
	"sync"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request)

// BusinessFlowModule handles sensitive business flow sub-scenarios.
type BusinessFlowModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager

	mu                 sync.Mutex
	sessionRedemptions map[string]map[string]bool
	userRedemptions    map[int]map[string]bool
	reservationStock   map[int]int
	userReservationQty map[string]int
}

func (m *BusinessFlowModule) Meta() core.ModuleMeta          { return m.meta }
func (m *BusinessFlowModule) APIRoutes() []core.APIRouteSpec { return m.apiRoutes }
func (m *BusinessFlowModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serveInfo(m, w, r)
}
func (m *BusinessFlowModule) ServeAPI(w http.ResponseWriter, r *http.Request) {
	m.serveAPI(m, w, r)
}
