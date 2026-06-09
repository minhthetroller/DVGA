package businessflow

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"

	"github.com/go-chi/chi/v5"
)

func currentSession(m *BusinessFlowModule, r *http.Request) (*session.Session, string) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, ""
	}
	return m.sess.Get(cookie.Value), cookie.Value
}

func promoCodeRedemptionMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "promo-code-redemption",
		Name:       "Promo Code Redemption",
		Category:   "Unrestricted Access to Sensitive Business Flows",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
		},
		Hints: [4]string{
			"Redeem a promo code through the API.",
			"Can the same code be redeemed repeatedly?",
			"Can a new session bypass the limit?",
			"Hard mode keys redemption to user ID and code.",
		},
	}
}

func servePromoCodeRedemptionInfo(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Promo Code Redemption</h3>
<p>POST <code>/api/v1/promotions/redeem</code> with JSON body <code>{"code":"SPRING50"}</code>.</p>`)
}

func servePromoCodeRedemptionAPI(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	sess, sessionToken := currentSession(m, r)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	body.Code = strings.ToUpper(strings.TrimSpace(body.Code))
	if body.Code == "" {
		jsonError(w, "code required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{"status": "redeemed", "code": body.Code, "discount_cents": 500})
	case core.Medium:
		m.mu.Lock()
		if m.sessionRedemptions[sessionToken] == nil {
			m.sessionRedemptions[sessionToken] = make(map[string]bool)
		}
		alreadyUsed := m.sessionRedemptions[sessionToken][body.Code]
		if !alreadyUsed {
			m.sessionRedemptions[sessionToken][body.Code] = true
		}
		m.mu.Unlock()
		if alreadyUsed {
			jsonError(w, "promo already redeemed in this session", http.StatusConflict)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "redeemed", "scope": "session", "code": body.Code})
	case core.Hard:
		m.mu.Lock()
		if m.userRedemptions[sess.UserID] == nil {
			m.userRedemptions[sess.UserID] = make(map[string]bool)
		}
		alreadyUsed := m.userRedemptions[sess.UserID][body.Code]
		if !alreadyUsed {
			m.userRedemptions[sess.UserID][body.Code] = true
		}
		m.mu.Unlock()
		if alreadyUsed {
			jsonError(w, "promo already redeemed by this account", http.StatusConflict)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "redeemed", "scope": "account", "code": body.Code})
	}
}

func flashSaleReservationMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "flash-sale-reservation",
		Name:       "Flash Sale Reservation",
		Category:   "Unrestricted Access to Sensitive Business Flows",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
		},
		Hints: [4]string{
			"Reserve flash sale inventory through the API.",
			"What happens with a very large quantity?",
			"Does the stock counter change globally?",
			"Hard mode enforces stock and per-user quantity.",
		},
	}
}

func serveFlashSaleReservationInfo(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Flash Sale Reservation</h3>
<p>POST <code>/api/v1/events/{id}/reserve</code> with JSON body <code>{"quantity":2}</code>.</p>`)
}

func serveFlashSaleReservationAPI(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	sess, _ := currentSession(m, r)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	eventID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid event id", http.StatusBadRequest)
		return
	}
	var body struct {
		Quantity int `json:"quantity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.Quantity <= 0 {
		jsonError(w, "quantity must be positive", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{"status": "reserved", "event_id": eventID, "quantity": body.Quantity})
	case core.Medium:
		if body.Quantity > 2 {
			jsonError(w, "maximum quantity is 2 per request", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "reserved", "event_id": eventID, "quantity": body.Quantity, "note": "stock not decremented"})
	case core.Hard:
		userKey := fmt.Sprintf("%d:%d", sess.UserID, eventID)
		m.mu.Lock()
		if _, ok := m.reservationStock[eventID]; !ok {
			m.reservationStock[eventID] = 5
		}
		currentUserQty := m.userReservationQty[userKey]
		stock := m.reservationStock[eventID]
		switch {
		case currentUserQty+body.Quantity > 2:
			m.mu.Unlock()
			jsonError(w, "per-user reservation limit exceeded", http.StatusTooManyRequests)
			return
		case stock < body.Quantity:
			m.mu.Unlock()
			jsonError(w, "not enough stock", http.StatusConflict)
			return
		}
		m.userReservationQty[userKey] += body.Quantity
		m.reservationStock[eventID] -= body.Quantity
		remaining := m.reservationStock[eventID]
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"status": "reserved", "event_id": eventID, "quantity": body.Quantity, "remaining_stock": remaining})
	}
}

func orderCancellationWindowMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "order-cancellation-window",
		Name:       "Order Cancellation Window",
		Category:   "Unrestricted Access to Sensitive Business Flows",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
		},
		Hints: [4]string{
			"Cancel an order through the API.",
			"Can shipped or old orders be cancelled?",
			"Does the server trust client-supplied status?",
			"Hard mode validates status and age from the database.",
		},
	}
}

func serveOrderCancellationWindowInfo(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Order Cancellation Window</h3>
<p>POST <code>/api/v1/orders/{id}/cancel</code> to cancel one of your orders.</p>`)
}

func serveOrderCancellationWindowAPI(m *BusinessFlowModule, w http.ResponseWriter, r *http.Request) {
	sess, _ := currentSession(m, r)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	orderID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid order id", http.StatusBadRequest)
		return
	}
	var order database.Order
	if err := m.store.DB().First(&order, orderID).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if int(order.UserID) != sess.UserID && sess.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var body struct {
		Status       string `json:"status"`
		WithinWindow bool   `json:"within_window"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		order.Status = "cancelled"
	case core.Medium:
		if body.Status != "pending" || !body.WithinWindow {
			jsonError(w, "order is outside cancellation window", http.StatusConflict)
			return
		}
		order.Status = "cancelled"
	case core.Hard:
		if order.Status != "pending" || time.Since(order.CreatedAt) > 48*time.Hour {
			jsonError(w, "order is outside cancellation window", http.StatusConflict)
			return
		}
		order.Status = "cancelled"
	}

	m.store.DB().Save(&order)
	json.NewEncoder(w).Encode(map[string]any{"status": "cancelled", "order_id": order.ID})
}
