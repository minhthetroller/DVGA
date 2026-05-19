// Package inventory implements Improper Inventory Management API vulnerability modules.
package inventory

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *InventoryModule, w http.ResponseWriter, r *http.Request)

// InventoryModule handles Improper Inventory Management sub-scenarios.
type InventoryModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager
}

func (m *InventoryModule) Meta() core.ModuleMeta          { return m.meta }
func (m *InventoryModule) APIRoutes() []core.APIRouteSpec { return m.apiRoutes }
func (m *InventoryModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serveInfo(m, w, r)
}
func (m *InventoryModule) ServeAPI(w http.ResponseWriter, r *http.Request) {
	m.serveAPI(m, w, r)
}
