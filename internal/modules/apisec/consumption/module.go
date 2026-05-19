// Package consumption implements Unsafe Consumption of APIs vulnerability modules.
package consumption

import (
	"net/http"
	"sync"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *ConsumptionModule, w http.ResponseWriter, r *http.Request)

// ConsumptionModule handles Unsafe Consumption of APIs sub-scenarios.
type ConsumptionModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager

	mu                sync.Mutex
	usedPaymentEvents map[string]bool
}

func (m *ConsumptionModule) Meta() core.ModuleMeta          { return m.meta }
func (m *ConsumptionModule) APIRoutes() []core.APIRouteSpec { return m.apiRoutes }
func (m *ConsumptionModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serveInfo(m, w, r)
}
func (m *ConsumptionModule) ServeAPI(w http.ResponseWriter, r *http.Request) {
	m.serveAPI(m, w, r)
}
