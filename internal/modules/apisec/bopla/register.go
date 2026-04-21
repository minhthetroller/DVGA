package bopla

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

// RegisterAll registers all BOPLA sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("profile-settings", func(d core.Difficulty) core.VulnModule {
		return &BOPLAModule{
			difficulty: d,
			meta:       profileSettingsMeta(d),
			serveInfo:  serveProfileSettingsInfo,
			serveAPI:   serveProfileSettingsAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPatch, Path: "/api/v1/members/me"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("order-details", func(d core.Difficulty) core.VulnModule {
		return &BOPLAModule{
			difficulty: d,
			meta:       orderDetailsMeta(d),
			serveInfo:  serveOrderDetailsInfo,
			serveAPI:   serveOrderDetailsAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodGet, Path: "/api/v1/orders/{id}/details"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("invoice-adjuster", func(d core.Difficulty) core.VulnModule {
		return &BOPLAModule{
			difficulty: d,
			meta:       invoiceAdjusterMeta(d),
			serveInfo:  serveInvoiceAdjusterInfo,
			serveAPI:   serveInvoiceAdjusterAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPatch, Path: "/api/v1/invoices/{id}"},
			},
			store: store,
			sess:  sess,
		}
	})
}
