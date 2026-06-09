package authfailures

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func userEnumerationMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "user-enumeration",
		Name:        "Account Recovery Lookup",
		Description: "Check whether an account can begin recovery.",
		Category:    "Identification and Authentication Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		},
		Hints: [4]string{
			"Recovery flows can reveal valid account identifiers.",
			"Compare responses for valid and invalid usernames.",
			"Look beyond visible text for hidden status metadata.",
			"Hard mode returns one uniform response for every lookup.",
		},
	}
}

func serveUserEnumeration(m *AuthFailuresModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		fmt.Fprint(w, ueRenderForm(""))
		return
	}

	var user database.User
	found := m.store.DB().Where("username = ?", username).First(&user).Error == nil

	switch m.difficulty {
	case core.Easy:
		if found {
			resp, _ := json.Marshal(map[string]any{"exists": true, "message": "Account found for " + user.Username})
			fmt.Fprint(w, ueRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
			return
		}
		resp, _ := json.Marshal(map[string]any{"exists": false, "message": "No account exists for " + username})
		fmt.Fprint(w, ueRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
	case core.Medium:
		status := "missing"
		if found {
			status = "exists"
		}
		fmt.Fprint(w, ueRenderForm(`<div class="output" data-account-status="`+status+`">If the account exists, recovery instructions will be sent.</div>`))
	case core.Hard:
		fmt.Fprint(w, ueRenderForm(`<div class="output">If the account exists, recovery instructions will be sent.</div>`))
	}
}

func ueRenderForm(output string) string {
	page := `<div class="vuln-form">
<h3>Account Recovery Lookup</h3>
<p>Enter a username to start account recovery.</p>
<form method="POST">
<label>Username: <input type="text" name="username" /></label>
<input type="submit" value="Continue" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page
}
