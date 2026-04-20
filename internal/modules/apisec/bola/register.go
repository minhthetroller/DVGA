package bola

import (
	"encoding/json"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RegisterAll registers all BOLA sub-vulnerabilities into the registry.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("member-profile", func(d core.Difficulty) core.VulnModule {
		return &BOLAModule{
			difficulty: d,
			meta:       memberProfileMeta(d),
			serveInfo:  serveMemberProfileInfo,
			serveAPI:   serveMemberProfileAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodGet, Path: "/api/v1/members/{id}"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("order-tracker", func(d core.Difficulty) core.VulnModule {
		return &BOLAModule{
			difficulty: d,
			meta:       orderTrackerMeta(d),
			serveInfo:  serveOrderTrackerInfo,
			serveAPI:   serveOrderTrackerAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodGet, Path: "/api/v1/orders/{id}"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("document-fetch", func(d core.Difficulty) core.VulnModule {
		return &BOLAModule{
			difficulty: d,
			meta:       documentFetchMeta(d),
			serveInfo:  serveDocumentFetchInfo,
			serveAPI:   serveDocumentFetchAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodGet, Path: "/api/v1/documents/{id}"},
			},
			store: store,
			sess:  sess,
		}
	})
}
