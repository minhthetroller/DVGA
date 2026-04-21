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

func cmdiMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "cmdi",
		Name:        "Network Diagnostics",
		Description: "Ping a host to check network connectivity.",
		Category:    "Injection",
		Difficulty:  d,
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

func serveCmdI(m *InjectionModule, w http.ResponseWriter, r *http.Request) {
	ip := r.FormValue("host")
	if ip == "" {
		fmt.Fprint(w, cmdiRenderForm(""))
		return
	}
	switch m.difficulty {
	case core.Easy:
		cmdiEasy(w, ip)
	case core.Medium:
		cmdiMedium(w, ip)
	case core.Hard:
		cmdiHard(w, ip)
	}
}

func cmdiEasy(w http.ResponseWriter, input string) {
	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("cmd", "/C", "ping -n 4 "+input).CombinedOutput()
	} else {
		out, _ = exec.Command("sh", "-c", "ping -c 4 "+input).CombinedOutput()
	}
	fmt.Fprint(w, cmdiRenderForm("<pre>"+string(out)+"</pre>"))
}

func cmdiMedium(w http.ResponseWriter, input string) {
	// Truncate at the first ; or && to prevent chained commands
	if idx := strings.Index(input, ";"); idx >= 0 {
		input = input[:idx]
	}
	if idx := strings.Index(input, "&&"); idx >= 0 {
		input = input[:idx]
	}
	sanitized := strings.TrimSpace(input)
	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("cmd", "/C", "ping -n 4 "+sanitized).CombinedOutput()
	} else {
		out, _ = exec.Command("sh", "-c", "ping -c 4 "+sanitized).CombinedOutput()
	}
	fmt.Fprint(w, cmdiRenderForm("<pre>"+string(out)+"</pre>"))
}

var ipRegex = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func cmdiHard(w http.ResponseWriter, input string) {
	input = strings.TrimSpace(input)
	if !ipRegex.MatchString(input) {
		fmt.Fprint(w, cmdiRenderForm(`<div class="error">Invalid IP address format.</div>`))
		return
	}
	var out []byte
	if runtime.GOOS == "windows" {
		out, _ = exec.Command("ping", "-n", "4", input).CombinedOutput()
	} else {
		out, _ = exec.Command("ping", "-c", "4", input).CombinedOutput()
	}
	fmt.Fprint(w, cmdiRenderForm("<pre>"+string(out)+"</pre>"))
}

func cmdiRenderForm(output string) string {
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


