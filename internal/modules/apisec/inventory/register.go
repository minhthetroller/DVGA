package inventory

import (
	"encoding/json"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RegisterAll registers all Improper Inventory Management sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("legacy-members-v0", func(d core.Difficulty) core.VulnModule {
		return &InventoryModule{
			difficulty: d,
			meta:       legacyMembersV0Meta(d),
			serveInfo:  serveLegacyMembersV0Info,
			serveAPI:   serveLegacyMembersV0API,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/v0/members/{id}"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("shadow-admin-users", func(d core.Difficulty) core.VulnModule {
		return &InventoryModule{
			difficulty: d,
			meta:       shadowAdminUsersMeta(d),
			serveInfo:  serveShadowAdminUsersInfo,
			serveAPI:   serveShadowAdminUsersAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/internal/users"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("stale-openapi", func(d core.Difficulty) core.VulnModule {
		return &InventoryModule{
			difficulty: d,
			meta:       staleOpenAPIMeta(d),
			serveInfo:  serveStaleOpenAPIInfo,
			serveAPI:   serveStaleOpenAPIAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/v1/openapi.json"}},
			store:      store,
			sess:       sess,
		}
	})
}
