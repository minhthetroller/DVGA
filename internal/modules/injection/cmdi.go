package injection

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"DVGA/internal/core"
)

// --- Factory ---

type CmdInjFactory struct{}

func (f *CmdInjFactory) Create(d core.Difficulty) core.VulnModule {
	return &CmdInjModule{difficulty: d}
}

// --- Module ---

type CmdInjModule struct {
	difficulty core.Difficulty
}

func (m *CmdInjModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "cmdi",
		Name:        "Network Diagnostics",
		Description: "Ping a host to check network connectivity.",
		Category:    "Injection",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://owasp.org/www-community/attacks/Command_Injection",
		},
		Hints: [4]string{
			"The server runs a system command for you",
			"What if the input is more than just a hostname?",
			"Shell metacharacters: | ; && $() are powerful",
			"Try: 127.0.0.1; cat /etc/passwd",
		},
	}
}

func (m *CmdInjModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := r.FormValue("host")
	if ip == "" {
		fmt.Fprint(w, m.renderForm(""))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, ip)
	case core.Medium:
		m.serveMedium(w, ip)
	case core.Hard:
		m.serveHard(w, ip)
	}
}

func (m *CmdInjModule) serveEasy(w http.ResponseWriter, input string) {
	// VULNERABLE: no filtering, shell execution
	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("cmd", "/C", "ping -n 4 "+input).CombinedOutput()
	} else {
		out, _ = exec.Command("sh", "-c", "ping -c 4 "+input).CombinedOutput()
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(out)+"</pre>"))
}

func (m *CmdInjModule) serveMedium(w http.ResponseWriter, input string) {
	// PARTIALLY VULNERABLE: blacklists && and ; but not | or $()
	sanitized := strings.ReplaceAll(input, "&&", "")
	sanitized = strings.ReplaceAll(sanitized, ";", "")

	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("cmd", "/C", "ping -n 4 "+sanitized).CombinedOutput()
	} else {
		out, _ = exec.Command("sh", "-c", "ping -c 4 "+sanitized).CombinedOutput()
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(out)+"</pre>"))
}

var ipRegex = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func (m *CmdInjModule) serveHard(w http.ResponseWriter, input string) {
	// SECURE: strict IP regex + no shell invocation
	input = strings.TrimSpace(input)
	if !ipRegex.MatchString(input) {
		fmt.Fprint(w, m.renderForm(`<div class="error">Invalid IP address format.</div>`))
		return
	}

	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("ping", "-n", "4", input).CombinedOutput()
	} else {
		out, _ = exec.Command("ping", "-c", "4", input).CombinedOutput()
	}
	fmt.Fprint(w, m.renderForm("<pre>"+string(out)+"</pre>"))
}

func (m *CmdInjModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Network Diagnostics</h3>
<p>Enter a host to check connectivity:</p>
<form method="POST">
<label>Host: <input type="text" name="host" placeholder="e.g. 8.8.8.8" /></label>
<input type="submit" value="Ping" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
