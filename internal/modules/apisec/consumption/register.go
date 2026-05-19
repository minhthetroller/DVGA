package consumption

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

// RegisterAll registers all Unsafe Consumption of APIs sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("payment-webhook", func(d core.Difficulty) core.VulnModule {
		return &ConsumptionModule{
			difficulty:        d,
			meta:              paymentWebhookMeta(d),
			serveInfo:         servePaymentWebhookInfo,
			serveAPI:          servePaymentWebhookAPI,
			apiRoutes:         []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/partners/payments/webhook"}},
			store:             store,
			sess:              sess,
			usedPaymentEvents: make(map[string]bool),
		}
	})
	reg.Register("crm-profile-sync", func(d core.Difficulty) core.VulnModule {
		return &ConsumptionModule{
			difficulty:        d,
			meta:              crmProfileSyncMeta(d),
			serveInfo:         serveCRMProfileSyncInfo,
			serveAPI:          serveCRMProfileSyncAPI,
			apiRoutes:         []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/partners/crm/profile"}},
			store:             store,
			sess:              sess,
			usedPaymentEvents: make(map[string]bool),
		}
	})
	reg.Register("shipping-status-sync", func(d core.Difficulty) core.VulnModule {
		return &ConsumptionModule{
			difficulty:        d,
			meta:              shippingStatusSyncMeta(d),
			serveInfo:         serveShippingStatusSyncInfo,
			serveAPI:          serveShippingStatusSyncAPI,
			apiRoutes:         []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/partners/shipping/status"}},
			store:             store,
			sess:              sess,
			usedPaymentEvents: make(map[string]bool),
		}
	})
}
