package brokenac

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// --- Factory ---

type PrivEscFactory struct {
	store *database.Store
	sess  *session.Manager
}

func (f *PrivEscFactory) Create(d core.Difficulty) core.VulnModule {
	return &PrivEscModule{
		difficulty: d,
		store:      f.store,
		sess:       f.sess,
	}
}

// --- Module ---

type PrivEscModule struct {
	difficulty core.Difficulty
	store      *database.Store
	sess       *session.Manager
}

func (m *PrivEscModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "privesc",
		Name:        "Team Management",
		Description: "Manage team members and roles.",
		Category:    "Broken Access Control",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Hints: [4]string{
			"Who decides what you can do?",
			"Is authorization checked on the server side?",
			"Try administrative actions as a normal user",
			"Send promote/delete requests directly — the server may not verify your role",
		},
	}
}

func (m *PrivEscModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, r)
	case core.Medium:
		m.serveMedium(w, r)
	case core.Hard:
		m.serveHard(w, r)
	}
}

func (m *PrivEscModule) serveEasy(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No server-side role check at all
	if r.Method == http.MethodPost {
		m.handleAdminAction(w, r)
		return
	}
	fmt.Fprint(w, m.renderAdminPanel(""))
}

func (m *PrivEscModule) serveMedium(w http.ResponseWriter, r *http.Request) {
	// PARTIALLY VULNERABLE: trusts client-side role cookie
	roleCookie, err := r.Cookie("role")
	if err != nil || roleCookie.Value != "admin" {
		fmt.Fprint(w, `<div class="vuln-form"><h3>Team Management</h3></div><div class="error">Access denied.</div>`)
		return
	}
	if r.Method == http.MethodPost {
		m.handleAdminAction(w, r)
		return
	}
	fmt.Fprint(w, m.renderAdminPanel(""))
}

func (m *PrivEscModule) serveHard(w http.ResponseWriter, r *http.Request) {
	// SECURE: server-side session role check
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	sess := m.sess.Get(cookie.Value)
	if sess == nil || sess.Role != "admin" {
		fmt.Fprint(w, `<div class="vuln-form"><h3>Team Management</h3></div><div class="error">Access denied.</div>`)
		return
	}
	if r.Method == http.MethodPost {
		m.handleAdminAction(w, r)
		return
	}
	fmt.Fprint(w, m.renderAdminPanel(""))
}

func (m *PrivEscModule) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	targetUser := r.FormValue("target_user")
	msg := ""
	switch action {
	case "delete":
		m.store.DB().Where("username = ? AND role != 'admin'", targetUser).Delete(&database.User{})
		msg = fmt.Sprintf("User '%s' removed.", targetUser)
	case "promote":
		m.store.DB().Model(&database.User{}).Where("username = ?", targetUser).Update("role", "admin")
		msg = fmt.Sprintf("User '%s' promoted.", targetUser)
	case "demote":
		m.store.DB().Model(&database.User{}).Where("username = ? AND username != 'admin'", targetUser).Update("role", "user")
		msg = fmt.Sprintf("User '%s' demoted.", targetUser)
	default:
		msg = "Unknown action."
	}
	fmt.Fprint(w, m.renderAdminPanel(msg))
}

func (m *PrivEscModule) renderAdminPanel(statusMsg string) string {
	var users []database.User
	m.store.DB().Find(&users)

	type member struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	var members []member
	for _, u := range users {
		members = append(members, member{ID: u.ID, Username: u.Username, Role: u.Role})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"team": members}, "", "  ")

	html := `<div class="vuln-form">
<h3>Team Management</h3>
</div>`

	if statusMsg != "" {
		html += `<div class="success">` + statusMsg + `</div>`
	}

	html += `<pre class="output">` + string(data) + `</pre>`

	// Action forms
	html += `<div class="vuln-form" style="margin-top:1rem">
<h4>Member Actions</h4>
<form method="POST" style="display:inline-block;margin-right:1rem">
<input type="text" name="target_user" placeholder="Username" />
<button name="action" value="promote">Promote</button>
<button name="action" value="demote">Demote</button>
<button name="action" value="delete">Remove</button>
</form>
</div>`
	return html
}
