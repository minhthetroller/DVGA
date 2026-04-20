package bopla

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"

	"github.com/go-chi/chi/v5"
)

// --- Profile Settings ---

func profileSettingsMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "profile-settings",
		Name:     "Profile Settings",
		Category: "Broken Object Property Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
		},
		Hints: [4]string{
			"Update your profile via the API.",
			"What fields does the PATCH accept?",
			"Try sending a 'role' field.",
			"The server binds the full struct — mass assignment.",
		},
	}
}

func serveProfileSettingsInfo(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")
	userID := 0
	if cookie != nil {
		if sess := m.sess.Get(cookie.Value); sess != nil {
			userID = sess.UserID
		}
	}
	fmt.Fprintf(w, `<h3>Profile Settings</h3>
<p>PATCH <code>/api/v1/members/me</code> with a JSON body to update your profile.</p>
<p>Your current user ID is <strong>%d</strong>.</p>`, userID)
}

func serveProfileSettingsAPI(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "application/json")

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}

	var user database.User
	if err := m.store.DB().First(&user, sess.UserID).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}

	switch m.difficulty {
	case core.Easy:
		// Mass assignment — binds everything including role
		if v, ok := body["username"].(string); ok {
			user.Username = v
		}
		if v, ok := body["email"].(string); ok {
			user.Email = v
		}
		if v, ok := body["phone"].(string); ok {
			user.Phone = v
		}
		if v, ok := body["role"].(string); ok {
			user.Role = v // vulnerability: role can be set
		}

	case core.Medium:
		// Blocklist "role" — other sensitive fields still writable
		delete(body, "role")
		if v, ok := body["username"].(string); ok {
			user.Username = v
		}
		if v, ok := body["email"].(string); ok {
			user.Email = v
		}
		if v, ok := body["phone"].(string); ok {
			user.Phone = v
		}
		if v, ok := body["password"].(string); ok {
			user.Password = v // vulnerability: password still writable without current pwd check
		}

	case core.Hard:
		// Allowlist — only display_name (phone) and email
		if v, ok := body["email"].(string); ok {
			user.Email = v
		}
		if v, ok := body["phone"].(string); ok {
			user.Phone = v
		}
	}

	m.store.DB().Save(&user)
	json.NewEncoder(w).Encode(map[string]any{
		"id": user.ID, "username": user.Username,
		"email": user.Email, "phone": user.Phone, "role": user.Role,
	})
}

// --- Order Details ---

func orderDetailsMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "order-details",
		Name:     "Order Details",
		Category: "Broken Object Property Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
		},
		Hints: [4]string{
			"Fetch an order via the API.",
			"What sensitive fields are in the response?",
			"CVV should never be returned.",
			"Only id, amount, and tracking should be visible.",
		},
	}
}

func serveOrderDetailsInfo(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Order Details</h3>
<p>GET <code>/api/v1/orders/{id}/details</code> to view order information.</p>`)
}

func serveOrderDetailsAPI(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var order database.Order
	if err := m.store.DB().First(&order, id).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{
			"id": order.ID, "user_id": order.UserID, "product": order.Product,
			"amount": order.Amount, "status": order.Status,
			"tracking_number": order.TrackingNumber, "card_last4": order.CardLast4, "cvv": order.CVV,
		})
	case core.Medium:
		json.NewEncoder(w).Encode(map[string]any{
			"id": order.ID, "user_id": order.UserID, "product": order.Product,
			"amount": order.Amount, "status": order.Status,
			"tracking_number": order.TrackingNumber, "card_last4": order.CardLast4,
		})
	case core.Hard:
		json.NewEncoder(w).Encode(map[string]any{
			"id": order.ID, "amount": order.Amount, "tracking_number": order.TrackingNumber,
		})
	}
}

// --- Invoice Adjuster ---

func invoiceAdjusterMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "invoice-adjuster",
		Name:     "Invoice Adjuster",
		Category: "Broken Object Property Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
		},
		Hints: [4]string{
			"PATCH an invoice to update its notes.",
			"Try changing the amount field.",
			"Can you set the status to 'paid'?",
			"Only 'notes' should be updatable by users.",
		},
	}
}

func serveInvoiceAdjusterInfo(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Invoice Adjuster</h3>
<p>PATCH <code>/api/v1/invoices/{id}</code> with a JSON body to update an invoice.</p>`)
}

func serveInvoiceAdjusterAPI(m *BOPLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var invoice database.Invoice
	if err := m.store.DB().First(&invoice, id).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		if v, ok := body["amount"].(float64); ok {
			invoice.Amount = v
		}
		if v, ok := body["status"].(string); ok {
			invoice.Status = v
		}
		if v, ok := body["notes"].(string); ok {
			invoice.Notes = v
		}
	case core.Medium:
		// Block amount but not status
		if v, ok := body["status"].(string); ok {
			invoice.Status = v
		}
		if v, ok := body["notes"].(string); ok {
			invoice.Notes = v
		}
	case core.Hard:
		// Allowlist: only notes
		if v, ok := body["notes"].(string); ok {
			invoice.Notes = v
		}
	}

	m.store.DB().Save(&invoice)
	json.NewEncoder(w).Encode(map[string]any{
		"id": invoice.ID, "amount": invoice.Amount,
		"status": invoice.Status, "notes": invoice.Notes,
	})
}
