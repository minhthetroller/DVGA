package bfla

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

// RegisterAll registers all BFLA sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("user-status-toggle", func(d core.Difficulty) core.VulnModule {
		return &BFLAModule{
			difficulty: d,
			meta:       userStatusToggleMeta(d),
			serveInfo:  serveUserStatusToggleInfo,
			serveAPI:   serveUserStatusToggleAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/members/{id}/suspend"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("support-tools", func(d core.Difficulty) core.VulnModule {
		return &BFLAModule{
			difficulty: d,
			meta:       supportToolsMeta(d),
			serveInfo:  serveSupportToolsInfo,
			serveAPI:   serveSupportToolsAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodGet, Path: "/api/v1/admin/dashboard"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("refund-processor", func(d core.Difficulty) core.VulnModule {
		return &BFLAModule{
			difficulty: d,
			meta:       refundProcessorMeta(d),
			serveInfo:  serveRefundProcessorInfo,
			serveAPI:   serveRefundProcessorAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/orders/{id}/refund"},
			},
			store: store,
			sess:  sess,
		}
	})
}
