package businessflow

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

// RegisterAll registers all Unrestricted Access to Sensitive Business Flows sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("promo-code-redemption", func(d core.Difficulty) core.VulnModule {
		return &BusinessFlowModule{
			difficulty:         d,
			meta:               promoCodeRedemptionMeta(d),
			serveInfo:          servePromoCodeRedemptionInfo,
			serveAPI:           servePromoCodeRedemptionAPI,
			apiRoutes:          []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/promotions/redeem"}},
			store:              store,
			sess:               sess,
			sessionRedemptions: make(map[string]map[string]bool),
			userRedemptions:    make(map[int]map[string]bool),
			reservationStock:   make(map[int]int),
			userReservationQty: make(map[string]int),
		}
	})
	reg.Register("flash-sale-reservation", func(d core.Difficulty) core.VulnModule {
		return &BusinessFlowModule{
			difficulty:         d,
			meta:               flashSaleReservationMeta(d),
			serveInfo:          serveFlashSaleReservationInfo,
			serveAPI:           serveFlashSaleReservationAPI,
			apiRoutes:          []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/events/{id}/reserve"}},
			store:              store,
			sess:               sess,
			sessionRedemptions: make(map[string]map[string]bool),
			userRedemptions:    make(map[int]map[string]bool),
			reservationStock:   make(map[int]int),
			userReservationQty: make(map[string]int),
		}
	})
	reg.Register("order-cancellation-window", func(d core.Difficulty) core.VulnModule {
		return &BusinessFlowModule{
			difficulty:         d,
			meta:               orderCancellationWindowMeta(d),
			serveInfo:          serveOrderCancellationWindowInfo,
			serveAPI:           serveOrderCancellationWindowAPI,
			apiRoutes:          []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/orders/{id}/cancel"}},
			store:              store,
			sess:               sess,
			sessionRedemptions: make(map[string]map[string]bool),
			userRedemptions:    make(map[int]map[string]bool),
			reservationStock:   make(map[int]int),
			userReservationQty: make(map[string]int),
		}
	})
}
