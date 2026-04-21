package crypto

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func weakPasswdMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "weak-passwd",
		Name:        "Admin Console",
		Description: "Administration user listing.",
		Category:    "Cryptographic Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		},
		Hints: [4]string{
			"The API response might include more than you expect",
			"Examine every field in the JSON response",
			"That hash is only 32 hex characters — what algorithm?",
			"MD5 with no salt — use rainbow tables or hashcat",
		},
	}
}

func serveWeakPasswd(m *CryptoModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.FormValue("action") == "verify" {
		wpHandleVerify(m, w, r)
		return
	}
	switch m.difficulty {
	case core.Easy:
		wpEasy(m, w)
	case core.Medium:
		wpMedium(m, w)
	case core.Hard:
		wpHard(m, w)
	}
}

func wpEasy(m *CryptoModule, w http.ResponseWriter) {
	var users []database.User
	m.store.DB().Find(&users)
	type userResp struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	results := make([]userResp, 0, len(users))
	for _, u := range users {
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role, Password: u.Password})
	}
	data, _ := json.MarshalIndent(map[string]any{"users": results}, "", "  ")
	fmt.Fprint(w, wpRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func wpMedium(m *CryptoModule, w http.ResponseWriter) {
	var users []database.User
	m.store.DB().Find(&users)
	type userResp struct {
		ID           uint   `json:"id"`
		Username     string `json:"username"`
		Role         string `json:"role"`
		PasswordHash string `json:"password_hash"`
	}
	results := make([]userResp, 0, len(users))
	for _, u := range users {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(u.Password)))
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role, PasswordHash: hash})
	}
	data, _ := json.MarshalIndent(map[string]any{"users": results}, "", "  ")
	fmt.Fprint(w, wpRenderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func wpHard(m *CryptoModule, w http.ResponseWriter) {
	var users []database.User
	m.store.DB().Find(&users)
	type userResp struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	results := make([]userResp, 0, len(users))
	for _, u := range users {
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role})
	}
	data, _ := json.MarshalIndent(map[string]any{"users": results}, "", "  ")
	output := `<pre class="output">` + string(data) + `</pre>`
	output += `<div class="vuln-form" style="margin-top:1rem">
<h4>Verify Password</h4>
<form method="POST">
<input type="hidden" name="action" value="verify" />
<label>Username: <input type="text" name="username" /></label>
<label>Password: <input type="password" name="guess" /></label>
<input type="submit" value="Verify" />
</form>
</div>`
	fmt.Fprint(w, wpRenderForm(output))
}

func wpHandleVerify(m *CryptoModule, w http.ResponseWriter, r *http.Request) {
	guess := r.FormValue("guess")
	username := r.FormValue("username")
	var user database.User
	if err := m.store.DB().Where("username = ?", username).First(&user).Error; err != nil {
		fmt.Fprint(w, wpRenderForm(`<div class="error">User not found.</div>`))
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	verified := bcrypt.CompareHashAndPassword(hash, []byte(guess)) == nil
	resp, _ := json.Marshal(map[string]any{"verified": verified, "username": username})
	fmt.Fprint(w, wpRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func wpRenderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Admin Console</h3>
<p>User administration panel.</p>
</div>`
	if output != "" {
		html += output
	}
	return html
}


