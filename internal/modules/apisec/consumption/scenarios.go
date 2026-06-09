package consumption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

const (
	paymentSharedToken = "partner-secret"
	paymentSigningKey  = "dvga-webhook-signing-secret"
	shippingCarrier    = "FastShip"
	shippingSigningKey = "dvga-carrier-signing-secret"
)

func currentSession(m *ConsumptionModule, r *http.Request) *session.Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	return m.sess.Get(cookie.Value)
}

func readJSONBody(w http.ResponseWriter, r *http.Request, dest any) ([]byte, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return raw, true
}

func validSignature(raw []byte, signature, key string) bool {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(raw)
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}

func paymentWebhookMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "payment-webhook",
		Name:       "Payment Webhook",
		Category:   "Unsafe Consumption of APIs",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
		},
		Hints: [4]string{
			"Send a payment provider webhook.",
			"Is the webhook signed?",
			"Is a static token enough?",
			"Hard mode verifies HMAC, amount, and idempotency.",
		},
	}
}

func servePaymentWebhookInfo(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Payment Webhook</h3>
<p>POST <code>/api/v1/partners/payments/webhook</code> with JSON body <code>{"invoice_id":2,"amount":149.50,"status":"paid"}</code>.</p>`)
}

func servePaymentWebhookAPI(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		InvoiceID uint    `json:"invoice_id"`
		Amount    float64 `json:"amount"`
		Status    string  `json:"status"`
	}
	raw, ok := readJSONBody(w, r, &body)
	if !ok {
		return
	}
	if body.Status == "" {
		body.Status = "paid"
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		updateInvoiceFromWebhook(m, w, body.InvoiceID, body.Status)
	case core.Medium:
		if r.Header.Get("X-Partner-Token") != paymentSharedToken {
			jsonError(w, "invalid partner token", http.StatusUnauthorized)
			return
		}
		updateInvoiceFromWebhook(m, w, body.InvoiceID, body.Status)
	case core.Hard:
		idempotencyKey := r.Header.Get("Idempotency-Key")
		if idempotencyKey == "" {
			jsonError(w, "idempotency key required", http.StatusBadRequest)
			return
		}
		if !validSignature(raw, r.Header.Get("X-Webhook-Signature"), paymentSigningKey) {
			jsonError(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var invoice database.Invoice
		if err := m.store.DB().First(&invoice, body.InvoiceID).Error; err != nil {
			jsonError(w, "invoice not found", http.StatusNotFound)
			return
		}
		if math.Abs(invoice.Amount-body.Amount) > 0.001 {
			jsonError(w, "amount mismatch", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		if m.usedPaymentEvents[idempotencyKey] {
			m.mu.Unlock()
			jsonError(w, "duplicate event", http.StatusConflict)
			return
		}
		m.usedPaymentEvents[idempotencyKey] = true
		m.mu.Unlock()
		invoice.Status = body.Status
		m.store.DB().Save(&invoice)
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "invoice_id": invoice.ID, "invoice_status": invoice.Status})
	}
}

func updateInvoiceFromWebhook(m *ConsumptionModule, w http.ResponseWriter, invoiceID uint, status string) {
	var invoice database.Invoice
	if err := m.store.DB().First(&invoice, invoiceID).Error; err != nil {
		jsonError(w, "invoice not found", http.StatusNotFound)
		return
	}
	invoice.Status = status
	m.store.DB().Save(&invoice)
	json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "invoice_id": invoice.ID, "invoice_status": invoice.Status})
}

func crmProfileSyncMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "crm-profile-sync",
		Name:       "CRM Profile Sync",
		Category:   "Unsafe Consumption of APIs",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
		},
		Hints: [4]string{
			"Sync a profile update from a partner CRM.",
			"Can partner data change your role?",
			"Can it update another user's profile?",
			"Hard mode binds the update to the current user.",
		},
	}
}

func serveCRMProfileSyncInfo(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>CRM Profile Sync</h3>
<p>POST <code>/api/v1/partners/crm/profile</code> with JSON body <code>{"user_id":2,"email":"new@example.com","phone":"555-0200"}</code>.</p>`)
}

func serveCRMProfileSyncAPI(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	sess := currentSession(m, r)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		UserID uint   `json:"user_id"`
		Email  string `json:"email"`
		Phone  string `json:"phone"`
		Role   string `json:"role"`
	}
	if _, ok := readJSONBody(w, r, &body); !ok {
		return
	}
	if body.UserID == 0 {
		body.UserID = uint(sess.UserID)
	}
	w.Header().Set("Content-Type", "application/json")

	if m.difficulty == core.Hard && int(body.UserID) != sess.UserID {
		jsonError(w, "cannot sync another user's profile", http.StatusForbidden)
		return
	}
	var user database.User
	if err := m.store.DB().First(&user, body.UserID).Error; err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if body.Email != "" {
		user.Email = body.Email
	}
	if body.Phone != "" {
		user.Phone = body.Phone
	}
	if m.difficulty == core.Easy && body.Role != "" {
		user.Role = body.Role
	}
	m.store.DB().Save(&user)
	json.NewEncoder(w).Encode(map[string]any{"status": "synced", "user_id": user.ID, "email": user.Email, "phone": user.Phone, "role": user.Role})
}

func shippingStatusSyncMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "shipping-status-sync",
		Name:       "Shipping Status Sync",
		Category:   "Unsafe Consumption of APIs",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
		},
		Hints: [4]string{
			"Sync order status from a carrier API.",
			"Can any status be pushed?",
			"Is a carrier header enough?",
			"Hard mode verifies signature and state transition.",
		},
	}
}

func serveShippingStatusSyncInfo(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Shipping Status Sync</h3>
<p>POST <code>/api/v1/partners/shipping/status</code> with JSON body <code>{"order_id":2,"status":"shipped"}</code>.</p>`)
}

func serveShippingStatusSyncAPI(m *ConsumptionModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrderID uint   `json:"order_id"`
		Status  string `json:"status"`
	}
	raw, ok := readJSONBody(w, r, &body)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch m.difficulty {
	case core.Easy:
		updateOrderStatus(m, w, body.OrderID, body.Status)
	case core.Medium:
		if r.Header.Get("X-Carrier") != shippingCarrier {
			jsonError(w, "invalid carrier", http.StatusUnauthorized)
			return
		}
		updateOrderStatus(m, w, body.OrderID, body.Status)
	case core.Hard:
		if !validSignature(raw, r.Header.Get("X-Carrier-Signature"), shippingSigningKey) {
			jsonError(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var order database.Order
		if err := m.store.DB().First(&order, body.OrderID).Error; err != nil {
			jsonError(w, "order not found", http.StatusNotFound)
			return
		}
		if !validOrderTransition(order.Status, body.Status) {
			jsonError(w, "invalid status transition", http.StatusConflict)
			return
		}
		order.Status = body.Status
		m.store.DB().Save(&order)
		json.NewEncoder(w).Encode(map[string]any{"status": "synced", "order_id": order.ID, "order_status": order.Status})
	}
}

func updateOrderStatus(m *ConsumptionModule, w http.ResponseWriter, orderID uint, status string) {
	var order database.Order
	if err := m.store.DB().First(&order, orderID).Error; err != nil {
		jsonError(w, "order not found", http.StatusNotFound)
		return
	}
	order.Status = status
	m.store.DB().Save(&order)
	json.NewEncoder(w).Encode(map[string]any{"status": "synced", "order_id": order.ID, "order_status": order.Status})
}

func validOrderTransition(from, to string) bool {
	switch from {
	case "pending":
		return to == "shipped" || to == "cancelled"
	case "shipped":
		return to == "delivered"
	default:
		return false
	}
}
