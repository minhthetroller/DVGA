package inventory

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"

	"github.com/go-chi/chi/v5"
)

func currentSession(m *InventoryModule, r *http.Request) *session.Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	return m.sess.Get(cookie.Value)
}

func legacyMembersV0Meta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "legacy-members-v0",
		Name:       "Legacy Members v0",
		Category:   "Improper Inventory Management",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
		},
		Hints: [4]string{
			"Try an older API version.",
			"Does v0 expose fields missing from v1?",
			"Deprecated is not the same as disabled.",
			"Hard mode removes the old endpoint.",
		},
	}
}

func serveLegacyMembersV0Info(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Legacy Members v0</h3>
<p>GET <code>/api/v0/members/{id}</code> to call the legacy member endpoint.</p>`)
}

func serveLegacyMembersV0API(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if m.difficulty == core.Hard {
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]any{"error": "legacy API retired"})
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var user database.User
	if err := m.store.DB().First(&user, id).Error; err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if m.difficulty == core.Medium {
		w.Header().Set("Deprecation", "true")
		w.Header().Set("Warning", `299 - "Deprecated API version still enabled"`)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"id":              user.ID,
		"username":        user.Username,
		"password":        user.Password,
		"role":            user.Role,
		"email":           user.Email,
		"phone":           user.Phone,
		"secret_question": user.SecretQuestion,
		"secret_answer":   user.SecretAnswer,
		"deprecated":      m.difficulty == core.Medium,
	})
}

func shadowAdminUsersMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "shadow-admin-users",
		Name:       "Shadow Admin Users",
		Category:   "Improper Inventory Management",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
		},
		Hints: [4]string{
			"Look for internal endpoints in the inventory.",
			"Can regular users call it?",
			"Does an internal header grant access?",
			"Hard mode checks the server-side role.",
		},
	}
}

func serveShadowAdminUsersInfo(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Shadow Admin Users</h3>
<p>GET <code>/api/internal/users</code> to call an undocumented user listing endpoint.</p>`)
}

func serveShadowAdminUsersAPI(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	sess := currentSession(m, r)
	if sess == nil {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch m.difficulty {
	case core.Easy:
		serveUserInventory(m, w, "undocumented")
	case core.Medium:
		if r.Header.Get("X-Internal") != "true" {
			jsonError(w, "internal network required", http.StatusForbidden)
			return
		}
		serveUserInventory(m, w, "x-internal")
	case core.Hard:
		if sess.Role != "admin" {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		serveUserInventory(m, w, "admin-session")
	}
}

func serveUserInventory(m *InventoryModule, w http.ResponseWriter, guard string) {
	var users []database.User
	m.store.DB().Find(&users)
	type userRow struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}
	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, userRow{ID: u.ID, Username: u.Username, Role: u.Role, Email: u.Email})
	}
	json.NewEncoder(w).Encode(map[string]any{"guard": guard, "users": rows})
}

func staleOpenAPIMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "stale-openapi",
		Name:       "Stale OpenAPI",
		Category:   "Improper Inventory Management",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
		},
		Hints: [4]string{
			"Download the advertised API inventory.",
			"Are deprecated endpoints listed?",
			"Are internal endpoints still advertised?",
			"Hard mode publishes only supported public APIs.",
		},
	}
}

func serveStaleOpenAPIInfo(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Stale OpenAPI</h3>
<p>GET <code>/api/v1/openapi.json</code> to inspect the API inventory.</p>`)
}

func serveStaleOpenAPIAPI(m *InventoryModule, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	paths := map[string]any{
		"/api/v1/members/{id}": map[string]any{"get": map[string]any{"summary": "Get member profile"}},
		"/api/v1/orders/{id}":  map[string]any{"get": map[string]any{"summary": "Track order"}},
	}
	switch m.difficulty {
	case core.Easy:
		paths["/api/v0/members/{id}"] = map[string]any{"get": map[string]any{"summary": "Legacy member profile"}}
		paths["/api/internal/users"] = map[string]any{"get": map[string]any{"summary": "Internal user inventory"}}
	case core.Medium:
		paths["/api/v0/members/{id}"] = map[string]any{"get": map[string]any{"summary": "Legacy member profile", "deprecated": true}}
		paths["/api/internal/users"] = map[string]any{"get": map[string]any{"summary": "Internal user inventory", "deprecated": true}}
	case core.Hard:
		paths["/api/v1/openapi.json"] = map[string]any{"get": map[string]any{"summary": "Supported API inventory"}}
	}
	json.NewEncoder(w).Encode(map[string]any{"openapi": "3.0.0", "paths": paths})
}
