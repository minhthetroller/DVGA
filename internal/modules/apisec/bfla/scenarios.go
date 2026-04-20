package bfla

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"

	"github.com/go-chi/chi/v5"
)

// --- User Status Toggle ---

func userStatusToggleMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "user-status-toggle",
		Name:     "User Status Toggle",
		Category: "Broken Function Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		},
		Hints: [4]string{
			"Admin endpoint to suspend users.",
			"What happens if you call it as a regular user?",
			"Try modifying the X-Role header.",
			"Hard mode checks the server-side session role.",
		},
	}
}

func serveUserStatusToggleInfo(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>User Status Toggle</h3>
<p>POST to <code>/api/v1/members/{id}/suspend</code> to suspend a user account (admin function).</p>`)
}

func serveUserStatusToggleAPI(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// No auth check
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if user.Role != "suspended" {
			user.Role = "suspended"
		} else {
			user.Role = "user"
		}
		m.store.DB().Save(&user)
		json.NewEncoder(w).Encode(map[string]any{"id": user.ID, "role": user.Role, "status": "toggled"})

	case core.Medium:
		// Trusts X-Role header
		role := r.Header.Get("X-Role")
		if role != "admin" {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if user.Role != "suspended" {
			user.Role = "suspended"
		} else {
			user.Role = "user"
		}
		m.store.DB().Save(&user)
		json.NewEncoder(w).Encode(map[string]any{"id": user.ID, "role": user.Role, "status": "toggled"})

	case core.Hard:
		// Server-side session check
		cookie, err := r.Cookie("session_id")
		if err != nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil || sess.Role != "admin" {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if user.Role != "suspended" {
			user.Role = "suspended"
		} else {
			user.Role = "user"
		}
		m.store.DB().Save(&user)
		json.NewEncoder(w).Encode(map[string]any{"id": user.ID, "role": user.Role, "status": "toggled"})
	}
}

// --- Support Tools (Admin Dashboard) ---

func supportToolsMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "support-tools",
		Name:     "Support Tools",
		Category: "Broken Function Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		},
		Hints: [4]string{
			"Admin dashboard accessible via API.",
			"Try calling it as a regular user.",
			"Check if a role cookie is the only guard.",
			"Hard mode requires admin or support session role.",
		},
	}
}

func serveSupportToolsInfo(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Support Tools</h3>
<p>GET <code>/api/v1/admin/dashboard</code> to view the admin dashboard.</p>`)
}

func serveSupportToolsAPI(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// Any authenticated user
		cookie, err := r.Cookie("session_id")
		if err != nil || m.sess.Get(cookie.Value) == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		serveDashboard(m, w)

	case core.Medium:
		// Role cookie check
		roleCookie, _ := r.Cookie("role")
		if roleCookie == nil || (roleCookie.Value != "admin" && roleCookie.Value != "support") {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		serveDashboard(m, w)

	case core.Hard:
		cookie, err := r.Cookie("session_id")
		if err != nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil || (sess.Role != "admin" && sess.Role != "support" && sess.Role != "helpdesk") {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		serveDashboard(m, w)
	}
}

func serveDashboard(m *BFLAModule, w http.ResponseWriter) {
	var users []database.User
	m.store.DB().Find(&users)
	type userSummary struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}
	summaries := make([]userSummary, len(users))
	for i, u := range users {
		summaries[i] = userSummary{ID: u.ID, Username: u.Username, Role: u.Role, Email: u.Email}
	}
	var orderCount, invoiceCount int64
	m.store.DB().Model(&database.Order{}).Count(&orderCount)
	m.store.DB().Model(&database.Invoice{}).Count(&invoiceCount)
	json.NewEncoder(w).Encode(map[string]any{
		"users": summaries, "total_orders": orderCount, "total_invoices": invoiceCount,
	})
}

// --- Refund Processor ---

func refundProcessorMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "refund-processor",
		Name:     "Refund Processor",
		Category: "Broken Function Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		},
		Hints: [4]string{
			"Refund an order via the API.",
			"Can regular users trigger refunds?",
			"Helpdesk can refund — any order?",
			"Hard: helpdesk can only refund their assigned orders.",
		},
	}
}

func serveRefundProcessorInfo(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Refund Processor</h3>
<p>POST to <code>/api/v1/orders/{id}/refund</code> to process a refund.</p>`)
}

func serveRefundProcessorAPI(m *BFLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// Any authenticated user
		cookie, err := r.Cookie("session_id")
		if err != nil || m.sess.Get(cookie.Value) == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		processRefund(m, w, id)

	case core.Medium:
		// Helpdesk role required, but no order assignment check
		cookie, err := r.Cookie("session_id")
		if err != nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil || (sess.Role != "helpdesk" && sess.Role != "admin") {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		processRefund(m, w, id)

	case core.Hard:
		// Helpdesk can only refund orders assigned to them
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
		if sess.Role == "admin" {
			processRefund(m, w, id)
			return
		}
		if (sess.Role == "helpdesk" || sess.Role == "support") && int(order.AssignedTo) == sess.UserID {
			processRefund(m, w, id)
			return
		}
		jsonError(w, "forbidden", http.StatusForbidden)
	}
}

func processRefund(m *BFLAModule, w http.ResponseWriter, id int) {
	var order database.Order
	if err := m.store.DB().First(&order, id).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	order.Status = "refunded"
	m.store.DB().Save(&order)
	json.NewEncoder(w).Encode(map[string]any{
		"id": order.ID, "status": order.Status, "message": "refund processed",
	})
}
