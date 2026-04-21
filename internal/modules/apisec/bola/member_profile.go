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

func memberProfileMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "member-profile",
		Name:     "Member Profile",
		Category: "Broken Object Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
		Hints: [4]string{
			"Who is this page showing?",
			"Where does the data come from?",
			"The page loads. Check what it loaded.",
			"Other members exist. Try their numbers.",
		},
	}
}

func serveMemberProfileInfo(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")
	userID := 0
	if cookie != nil {
		if sess := m.sess.Get(cookie.Value); sess != nil {
			userID = sess.UserID
		}
	}
	fmt.Fprintf(w, memberProfileHTML, userID, userID)
}

func serveMemberProfileAPI(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch m.difficulty {
	case core.Easy:
		// No auth check — return any member by ID
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(memberJSON(user))

	case core.Medium:
		// Trusts X-User-Id header — bypassable
		claimedID, _ := strconv.Atoi(r.Header.Get("X-User-Id"))
		if claimedID != id {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(memberJSON(user))

	case core.Hard:
		// Proper server-side enforcement
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
		if sess.Role != "admin" && sess.UserID != id {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var user database.User
		if err := m.store.DB().First(&user, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(memberJSON(user))
	}
}

func memberJSON(u database.User) map[string]any {
	return map[string]any{
		"id":       u.ID,
		"username": u.Username,
		"role":     u.Role,
		"email":    u.Email,
		"phone":    u.Phone,
	}
}

const memberProfileHTML = `<div class="member-card" style="border:1px solid #ccc;border-radius:8px;padding:1.5rem;max-width:400px">
<div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem">
<div style="width:56px;height:56px;border-radius:50%%;background:#6c63ff;display:flex;align-items:center;justify-content:center;color:white;font-size:1.5rem">&#128100;</div>
<div id="profile-header"><p style="color:#888">Loading…</p></div>
</div>
<table id="profile-table" style="width:100%%"></table>
</div>
<script>
(function(){
  fetch('/api/v1/members/%d')
    .then(function(r){return r.json();})
    .then(function(d){
      document.getElementById('profile-header').innerHTML =
        '<h4 style="margin:0">'+d.username+'</h4><small style="color:#888">'+d.role+'</small>';
      var rows='';
      if(d.email) rows+='<tr><td><b>Email</b></td><td>'+d.email+'</td></tr>';
      if(d.phone) rows+='<tr><td><b>Phone</b></td><td>'+d.phone+'</td></tr>';
      document.getElementById('profile-table').innerHTML=rows;
    })
    .catch(function(){document.getElementById('profile-header').innerHTML='<p style="color:red">Failed to load</p>';});
  window._memberId = %d;
})();
</script>`
