package brokenac

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func privEscMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "privesc",
		Name:        "Team Management",
		Description: "Manage team members and roles.",
		Category:    "Broken Access Control",
		Difficulty:  d,
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

func servePrivEsc(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
	switch m.difficulty {
	case core.Easy:
		privEscEasy(m, w, r)
	case core.Medium:
		privEscMedium(m, w, r)
	case core.Hard:
		privEscHard(m, w, r)
	}
}

func privEscEasy(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		privEscHandleAction(m, w, r)
		return
	}
	fmt.Fprint(w, privEscRenderPanel(m, ""))
}

func privEscMedium(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
	roleCookie, err := r.Cookie("role")
	if err != nil || roleCookie.Value != "admin" {
		fmt.Fprint(w, `<div class="vuln-form"><h3>Team Management</h3></div><div class="error">Access denied.</div>`)
		return
	}
	if r.Method == http.MethodPost {
		privEscHandleAction(m, w, r)
		return
	}
	fmt.Fprint(w, privEscRenderPanel(m, ""))
}

func privEscHard(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
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
		privEscHandleAction(m, w, r)
		return
	}
	fmt.Fprint(w, privEscRenderPanel(m, ""))
}

func privEscHandleAction(m *BrokenACModule, w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	targetUser := r.FormValue("target_user")
	var msg string
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
	fmt.Fprint(w, privEscRenderPanel(m, msg))
}

func privEscRenderPanel(m *BrokenACModule, statusMsg string) string {
	var users []database.User
	m.store.DB().Find(&users)

	type member struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	members := make([]member, 0, len(users))
	for _, u := range users {
		members = append(members, member{ID: u.ID, Username: u.Username, Role: u.Role})
	}
	data, _ := json.MarshalIndent(map[string]any{"team": members}, "", "  ")

	html := `<div class="vuln-form"><h3>Team Management</h3></div>`
	if statusMsg != "" {
		html += `<div class="success">` + statusMsg + `</div>`
	}
	html += `<pre class="output">` + string(data) + `</pre>`
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

