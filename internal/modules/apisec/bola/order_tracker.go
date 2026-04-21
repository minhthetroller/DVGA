package bola

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"

	"github.com/go-chi/chi/v5"
)

func orderTrackerMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "order-tracker",
		Name:     "Order Tracker",
		Category: "Broken Object Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
		Hints: [4]string{
			"You can track an order.",
			"What if you knew another order number?",
			"The response contains more than tracking info.",
			"Card details are included in the response.",
		},
	}
}

func serveOrderTrackerInfo(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")
	userID := 0
	if cookie != nil {
		if sess := m.sess.Get(cookie.Value); sess != nil {
			userID = sess.UserID
		}
	}
	var orders []database.Order
	m.store.DB().Where("user_id = ?", userID).Limit(5).Find(&orders)
	list := ""
	for _, o := range orders {
		list += fmt.Sprintf("<li>Order #%d — %s — $%.2f [<a href='/api/v1/orders/%d'>Track</a>]</li>", o.ID, o.Product, o.Amount, o.ID)
	}
	if list == "" {
		list = "<li>No orders found. Try logging in.</li>"
	}
	fmt.Fprintf(w, `<h3>Your Orders</h3><ul>%s</ul>`, list)
}

func serveOrderTrackerAPI(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// No auth — return any order
		var order database.Order
		if err := m.store.DB().First(&order, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(orderJSONFull(order))

	case core.Medium:
		// Auth required but no ownership check
		cookie, err := r.Cookie("session_id")
		if err != nil || m.sess.Get(cookie.Value) == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var order database.Order
		if err := m.store.DB().First(&order, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(orderJSONFull(order))

	case core.Hard:
		// Ownership check
		cookie, err := r.Cookie("session_id")
		if err != nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var order database.Order
		if err := m.store.DB().First(&order, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if sess.Role != "admin" && int(order.UserID) != sess.UserID {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(orderJSONSafe(order))
	}
}

func orderJSONFull(o database.Order) map[string]any {
	return map[string]any{
		"id": o.ID, "user_id": o.UserID, "product": o.Product,
		"amount": o.Amount, "status": o.Status,
		"tracking_number": o.TrackingNumber, "card_last4": o.CardLast4, "cvv": o.CVV,
	}
}

func orderJSONSafe(o database.Order) map[string]any {
	return map[string]any{
		"id": o.ID, "product": o.Product, "amount": o.Amount,
		"status": o.Status, "tracking_number": o.TrackingNumber,
	}
}
