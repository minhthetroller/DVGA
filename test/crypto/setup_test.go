package cryptoctest

import (
"encoding/json"
"fmt"
"io"
"net/http"
"net/http/httptest"
"net/url"
"strings"
"sync"
"testing"

"DVGA/internal/core"
"DVGA/internal/database"
"DVGA/internal/modules/apisec/bfla"
"DVGA/internal/modules/apisec/bola"
"DVGA/internal/modules/apisec/bopla"
"DVGA/internal/modules/apisec/brokenauth"
"DVGA/internal/modules/apisec/resource"
"DVGA/internal/modules/brokenac"
"DVGA/internal/modules/crypto"
"DVGA/internal/modules/injection"
"DVGA/internal/modules/insecuredesign"
"DVGA/internal/modules/misconfig"
"DVGA/internal/session"

"github.com/go-chi/chi/v5"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

const (
adminUsername = "admin"
adminPassword = "admin"

gordonUsername = "gordonb"
gordonPassword = "abc123"

pabloUsername = "pablo"
pabloPassword = "letmein"

leetUsername = "1337"
leetPassword = "charley"

helpdeskUsername = "helpdesk"
helpdeskPassword = "help1234"

supportUsername = "support"
supportPassword = "support1"
)

type testApp struct {
store      *database.Store
sessions   *session.Manager
registry   *core.Registry
difficulty *core.SafeDifficulty
server     *httptest.Server
t          *testing.T
modCache   map[string]core.VulnModule
modMu      sync.Mutex
}

func newTestApp(t *testing.T) *testApp {
t.Helper()

store, err := database.NewStore(":memory:")
if err != nil {
t.Fatalf("newTestApp: open store: %v", err)
}
if err := store.AutoMigrate(); err != nil {
t.Fatalf("newTestApp: migrate: %v", err)
}
if err := store.Seed(); err != nil {
t.Fatalf("newTestApp: seed: %v", err)
}

sessions := session.NewManager()
diff := core.NewSafeDifficulty(core.Easy)
registry := core.NewRegistry()

brokenac.RegisterAll(registry, store, sessions)
crypto.RegisterAll(registry, store)
injection.RegisterAll(registry, store)
insecuredesign.RegisterAll(registry, store, sessions)
misconfig.RegisterAll(registry, store)
bola.RegisterAll(registry, store, sessions)
brokenauth.RegisterAll(registry, store, sessions)
bopla.RegisterAll(registry, store, sessions)
resource.RegisterAll(registry, store, sessions)
bfla.RegisterAll(registry, store, sessions)

app := &testApp{
store:      store,
sessions:   sessions,
registry:   registry,
difficulty: diff,
t:          t,
modCache:   make(map[string]core.VulnModule),
}

r := app.buildRouter()
app.server = httptest.NewServer(r)
t.Cleanup(func() { app.server.Close() })

return app
}

func (a *testApp) setDifficulty(d core.Difficulty) { a.difficulty.Set(d) }

func (a *testApp) login(username, password string) (string, bool) {
var user database.User
if err := a.store.DB().Where("username = ? AND password = ?", username, password).
First(&user).Error; err != nil {
return "", false
}
token := a.sessions.Create(int(user.ID), user.Username, user.Role)
return token, true
}

func (a *testApp) mustLogin(username, password string) string {
a.t.Helper()
token, ok := a.login(username, password)
if !ok {
a.t.Fatalf("mustLogin: rejected credentials for %q", username)
}
return token
}

func (a *testApp) sessionCookie(token string) *http.Cookie {
return &http.Cookie{Name: "session_id", Value: token}
}

func (a *testApp) buildModule(id string) core.VulnModule {
a.t.Helper()
m, err := a.registry.Build(id, a.difficulty.Get())
if err != nil {
a.t.Fatalf("buildModule(%q): %v", id, err)
}
return m
}

func (a *testApp) requireAuth(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
cookie, err := r.Cookie("session_id")
if err != nil || cookie.Value == "" {
http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
return
}
if a.sessions.Get(cookie.Value) == nil {
http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
return
}
next.ServeHTTP(w, r)
})
}

func (a *testApp) buildRouter() chi.Router {
r := chi.NewRouter()

for _, id := range a.registry.IDs() {
mod, err := a.registry.Build(id, a.difficulty.Get())
if err != nil {
continue
}
apiMod, ok := mod.(core.APIModule)
if !ok {
continue
}
for _, rt := range apiMod.APIRoutes() {
path := rt.Path
modID := id
isAuthPath := path == "/api/v1/auth/token" || path == "/api/v1/auth/refresh"
handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
d := a.difficulty.Get()
cacheKey := fmt.Sprintf("%s:%d", modID, d)
a.modMu.Lock()
cached, found := a.modCache[cacheKey]
if !found {
m, err := a.registry.Build(modID, d)
if err != nil {
a.modMu.Unlock()
http.NotFound(w, req)
return
}
a.modCache[cacheKey] = m
cached = m
}
a.modMu.Unlock()
if am, ok := cached.(core.APIModule); ok {
am.ServeAPI(w, req)
}
})
if isAuthPath {
r.Method(rt.Method, path, handler)
} else {
r.With(a.requireAuth).Method(rt.Method, path, handler)
}
}
}

return r
}

func doModuleRequest(t *testing.T, app *testApp, id, method, rawURL string, body io.Reader, cookies ...*http.Cookie) *httptest.ResponseRecorder {
t.Helper()
mod := app.buildModule(id)
req := httptest.NewRequest(method, rawURL, body)
if method == http.MethodPost && body != nil {
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
}
for _, c := range cookies {
req.AddCookie(c)
}
w := httptest.NewRecorder()
mod.ServeHTTP(w, req)
return w
}

func doAPIRequest(t *testing.T, app *testApp, method, path, jsonBody string, cookies ...*http.Cookie) *http.Response {
t.Helper()
var bodyReader io.Reader
if jsonBody != "" {
bodyReader = strings.NewReader(jsonBody)
}
req, err := http.NewRequest(method, app.server.URL+path, bodyReader)
require.NoError(t, err)
if jsonBody != "" {
req.Header.Set("Content-Type", "application/json")
}
for _, c := range cookies {
req.AddCookie(c)
}
client := &http.Client{
CheckRedirect: func(*http.Request, []*http.Request) error {
return http.ErrUseLastResponse
},
}
resp, err := client.Do(req)
require.NoError(t, err)
return resp
}

func doAPIRequestWithHeader(t *testing.T, app *testApp, method, path, jsonBody string, headers map[string]string, cookies ...*http.Cookie) *http.Response {
t.Helper()
var bodyReader io.Reader
if jsonBody != "" {
bodyReader = strings.NewReader(jsonBody)
}
req, err := http.NewRequest(method, app.server.URL+path, bodyReader)
require.NoError(t, err)
if jsonBody != "" {
req.Header.Set("Content-Type", "application/json")
}
for k, v := range headers {
req.Header.Set(k, v)
}
for _, c := range cookies {
req.AddCookie(c)
}
client := &http.Client{
CheckRedirect: func(*http.Request, []*http.Request) error {
return http.ErrUseLastResponse
},
}
resp, err := client.Do(req)
require.NoError(t, err)
return resp
}

func readBody(t *testing.T, resp *http.Response) string {
t.Helper()
b, err := io.ReadAll(resp.Body)
require.NoError(t, err)
resp.Body.Close()
return string(b)
}

func parseJSON(t *testing.T, body string) map[string]any {
t.Helper()
var m map[string]any
err := json.Unmarshal([]byte(strings.TrimSpace(body)), &m)
require.NoError(t, err, "parseJSON: body was: %s", body)
return m
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
t.Helper()
assert.Equal(t, want, resp.StatusCode, "unexpected HTTP status")
}

func assertContains(t *testing.T, haystack, needle string) {
t.Helper()
assert.Contains(t, haystack, needle)
}

func assertNotContains(t *testing.T, haystack, needle string) {
t.Helper()
assert.NotContains(t, haystack, needle)
}

func roleCookie(role string) *http.Cookie {
return &http.Cookie{Name: "role", Value: role}
}

func formBody(kvPairs ...string) io.Reader {
if len(kvPairs)%2 != 0 {
panic("formBody: must receive an even number of key-value arguments")
}
vals := url.Values{}
for i := 0; i < len(kvPairs); i += 2 {
vals.Set(kvPairs[i], kvPairs[i+1])
}
return strings.NewReader(vals.Encode())
}

func allDifficulties() []core.Difficulty {
return []core.Difficulty{core.Easy, core.Medium, core.Hard}
}
