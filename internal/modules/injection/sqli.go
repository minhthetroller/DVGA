package injection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type SQLiFactory struct {
	store *database.Store
}

func (f *SQLiFactory) Create(d core.Difficulty) core.VulnModule {
	return &SQLiModule{difficulty: d, store: f.store}
}

// --- Module ---

type SQLiModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *SQLiModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "sqli",
		Name:        "Employee Directory",
		Description: "Look up employee information by ID.",
		Category:    "Injection",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
		Hints: [4]string{
			"Data has to come from somewhere",
			"What happens with unexpected input types?",
			"A single character can break a query",
			"UNION SELECT with matching column count",
		},
	}
}

func (m *SQLiModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("id")
	if input == "" {
		fmt.Fprint(w, m.renderForm(""))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, input)
	case core.Medium:
		m.serveMedium(w, input)
	case core.Hard:
		m.serveHard(w, input)
	}
}

func (m *SQLiModule) serveEasy(w http.ResponseWriter, input string) {
	// VULNERABLE: direct string concatenation
	query := "SELECT id, username, password, role, secret_question, secret_answer FROM users WHERE id = '" + input + "'"
	rows, err := m.store.DB().Raw(query).Rows()
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">No results found.</div>`))
		return
	}
	defer rows.Close()

	type employee struct {
		ID         interface{} `json:"id"`
		Name       interface{} `json:"name"`
		Department interface{} `json:"department"`
		Title      interface{} `json:"title"`
		Email      interface{} `json:"email"`
		Notes      interface{} `json:"notes"`
	}

	cols, _ := rows.Columns()
	var results []employee
	for rows.Next() {
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		e := employee{}
		if len(values) > 0 {
			e.ID = values[0]
		}
		if len(values) > 1 {
			e.Name = values[1]
		}
		if len(values) > 2 {
			e.Department = values[2]
		}
		if len(values) > 3 {
			e.Title = values[3]
		}
		if len(values) > 4 {
			e.Email = values[4]
		}
		if len(values) > 5 {
			e.Notes = values[5]
		}
		results = append(results, e)
	}

	if len(results) == 0 {
		fmt.Fprint(w, m.renderForm(`<div class="error">No results found.</div>`))
		return
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"employees": results}, "", "  ")
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *SQLiModule) serveMedium(w http.ResponseWriter, input string) {
	if _, err := strconv.Atoi(input); err == nil {
		query := "SELECT id, username, role FROM users WHERE id = " + input
		rows, err := m.store.DB().Raw(query).Rows()
		if err != nil {
			fmt.Fprint(w, m.renderForm(`<div class="error">No results found.</div>`))
			return
		}
		defer rows.Close()
		fmt.Fprint(w, m.renderForm(m.formatRowsMedium(rows)))
		return
	}
	escaped := strings.ReplaceAll(input, "'", "\\'")
	query := "SELECT id, username, role FROM users WHERE id = '" + escaped + "'"
	rows, err := m.store.DB().Raw(query).Rows()
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">No results found.</div>`))
		return
	}
	defer rows.Close()
	fmt.Fprint(w, m.renderForm(m.formatRowsMedium(rows)))
}

func (m *SQLiModule) serveHard(w http.ResponseWriter, input string) {
	var users []database.User
	m.store.DB().Where("id = ?", input).Find(&users)
	if len(users) == 0 {
		fmt.Fprint(w, m.renderForm(`<div class="error">No results found.</div>`))
		return
	}
	type emp struct {
		ID         uint   `json:"id"`
		Name       string `json:"name"`
		Department string `json:"department"`
	}
	var results []emp
	for _, u := range users {
		results = append(results, emp{ID: u.ID, Name: u.Username, Department: u.Role})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"employees": results}, "", "  ")
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *SQLiModule) formatRowsMedium(rows interface{ Next() bool; Scan(...any) error }) string {
	type emp struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		Department string `json:"department"`
	}
	var results []emp
	for rows.Next() {
		var id int
		var username, role string
		if err := rows.Scan(&id, &username, &role); err != nil {
			continue
		}
		results = append(results, emp{ID: id, Name: username, Department: role})
	}
	if len(results) == 0 {
		return `<div class="error">No results found.</div>`
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"employees": results}, "", "  ")
	return `<pre class="output">` + string(data) + `</pre>`
}

func (m *SQLiModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Employee Directory</h3>
<p>Look up an employee by their ID:</p>
<form method="GET">
<label>Employee ID: <input type="text" name="id" /></label>
<input type="submit" value="Search" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
