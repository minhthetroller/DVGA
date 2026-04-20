package resource

import (
	"net/http"
	"sync"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *ResourceModule, w http.ResponseWriter, r *http.Request)

// ResourceModule handles Unrestricted Resource Consumption sub-scenarios.
type ResourceModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serveInfo  scenarioFunc
	serveAPI   scenarioFunc
	apiRoutes  []core.APIRouteSpec
	store      *database.Store
	sess       *session.Manager

	// Per-instance counters for rate limiting (avoids test pollution from globals).
	IPMu            sync.Mutex
	IPCounters      map[string]int
	AccountMu       sync.Mutex
	AccountCounters map[int]int
}

func (m *ResourceModule) Meta() core.ModuleMeta              { return m.meta }
func (m *ResourceModule) APIRoutes() []core.APIRouteSpec     { return m.apiRoutes }
func (m *ResourceModule) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serveInfo(m, w, r) }
func (m *ResourceModule) ServeAPI(w http.ResponseWriter, r *http.Request)  { m.serveAPI(m, w, r) }
