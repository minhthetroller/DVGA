package ui

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

type Handler struct {
	renderer   *TemplateRenderer
	registry   *core.Registry
	chain      *core.Chain
	store      *database.Store
	sessions   *session.Manager
	difficulty *core.SafeDifficulty
	staticDir  string
	logger     zerolog.Logger

	// sidebar cache
	sidebarMu         sync.RWMutex
	sidebarCache      []SidebarCategory
	sidebarDifficulty core.Difficulty
	sidebarReady      bool
}

func NewHandler(
	renderer *TemplateRenderer,
	registry *core.Registry,
	chain *core.Chain,
	store *database.Store,
	sessions *session.Manager,
	difficulty *core.SafeDifficulty,
	staticDir string,
	logger zerolog.Logger,
) *Handler {
	return &Handler{
		renderer:   renderer,
		registry:   registry,
		chain:      chain,
		store:      store,
		sessions:   sessions,
		difficulty: difficulty,
		staticDir:  staticDir,
		logger:     logger,
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	// Static files
	fs := http.StripPrefix("/static/", http.FileServer(http.Dir(h.staticDir)))
	r.Handle("/static/*", fs)

	// Auth routes (no session required)
	r.Get("/login", h.loginPage)
	r.Post("/login", h.loginSubmit)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(h.requireAuth)

		r.Get("/", h.homePage)
		r.Get("/logout", h.logoutPage)
		r.Get("/security", h.securityPage)
		r.Post("/security", h.securitySubmit)
		r.Get("/setup", h.setupPage)
		r.Post("/setup", h.setupSubmit)
		r.Get("/about", h.aboutPage)

		// Vulnerability module routes
		r.HandleFunc("/vulnerabilities/{moduleID}", h.modulePage)
		r.Get("/vulnerabilities/{moduleID}/hint", h.hintAPI)
	})

	return r
}

// --- Auth middleware ---

func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess := h.sessions.Get(cookie.Value)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Pages ---

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{PageTitle: "Login"}
	h.renderer.Render(w, "login", data)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var user database.User
	if err := h.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		data := PageData{PageTitle: "Login", Content: "Invalid username or password."}
		h.renderer.Render(w, "login", data)
		return
	}

	token := h.sessions.Create(int(user.ID), user.Username, user.Role)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logoutPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_id"); err == nil {
		h.sessions.Destroy(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) homePage(w http.ResponseWriter, r *http.Request) {
	sess := h.getSession(r)
	data := h.baseData("Home", "home", sess)
	h.renderPage(w, "home", data)
}

func (h *Handler) securityPage(w http.ResponseWriter, r *http.Request) {
	sess := h.getSession(r)
	data := h.baseData("Security", "security", sess)
	h.renderPage(w, "security", data)
}

func (h *Handler) securitySubmit(w http.ResponseWriter, r *http.Request) {
	h.difficulty.Set(core.ParseDifficulty(r.FormValue("difficulty")))
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (h *Handler) setupPage(w http.ResponseWriter, r *http.Request) {
	sess := h.getSession(r)
	data := h.baseData("Setup", "setup", sess)
	h.renderPage(w, "setup", data)
}

func (h *Handler) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Reset(); err != nil {
		h.logger.Error().Err(err).Msg("database reset failed")
	}
	sess := h.getSession(r)
	data := h.baseData("Setup", "setup", sess)
	data.Content = "Database has been reset successfully."
	h.renderPage(w, "setup", data)
}

func (h *Handler) aboutPage(w http.ResponseWriter, r *http.Request) {
	sess := h.getSession(r)
	data := h.baseData("About", "about", sess)
	h.renderPage(w, "about", data)
}

func (h *Handler) modulePage(w http.ResponseWriter, r *http.Request) {
	moduleID := chi.URLParam(r, "moduleID")

	mod, err := h.registry.Build(moduleID, h.difficulty.Get())
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Apply decorator chain
	wrapped := h.chain.Apply(mod)

	// Capture module output
	var buf bytes.Buffer
	rec := &responseRecorder{ResponseWriter: w, body: &buf}
	wrapped.ServeHTTP(rec, r)

	sess := h.getSession(r)
	data := h.baseData(mod.Meta().Name, moduleID, sess)
	data.Content = template.HTML(buf.String())
	data.MoreInfo = mod.Meta().References
	h.renderPage(w, "module", data)
}

// --- Helpers ---

func (h *Handler) getSession(r *http.Request) *session.Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	return h.sessions.Get(cookie.Value)
}

func (h *Handler) baseData(title, activeID string, sess *session.Session) PageData {
	username := ""
	if sess != nil {
		username = sess.Username
	}
	return PageData{
		PageTitle:  title,
		Username:   username,
		Difficulty: h.difficulty.Get().String(),
		ActiveID:   activeID,
		Sidebar:    h.buildSidebar(),
	}
}

func (h *Handler) buildSidebar() []SidebarCategory {
	current := h.difficulty.Get()

	// Check cache
	h.sidebarMu.RLock()
	if h.sidebarReady && h.sidebarDifficulty == current {
		cached := h.sidebarCache
		h.sidebarMu.RUnlock()
		return cached
	}
	h.sidebarMu.RUnlock()

	// Rebuild
	catMap := make(map[string][]SidebarItem)
	for _, mod := range h.registry.All(current) {
		meta := mod.Meta()
		catMap[meta.Category] = append(catMap[meta.Category], SidebarItem{
			ID:   meta.ID,
			Name: meta.Name,
			URL:  "/vulnerabilities/" + meta.ID,
		})
	}

	catNames := make([]string, 0, len(catMap))
	for name := range catMap {
		catNames = append(catNames, name)
	}
	sort.Strings(catNames)

	sidebar := make([]SidebarCategory, 0, len(catNames))
	for _, name := range catNames {
		items := catMap[name]
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		sidebar = append(sidebar, SidebarCategory{Name: name, Items: items})
	}

	// Store in cache
	h.sidebarMu.Lock()
	h.sidebarCache = sidebar
	h.sidebarDifficulty = current
	h.sidebarReady = true
	h.sidebarMu.Unlock()

	return sidebar
}

func (h *Handler) hintAPI(w http.ResponseWriter, r *http.Request) {
	moduleID := chi.URLParam(r, "moduleID")
	levelStr := r.URL.Query().Get("level")

	level, err := strconv.Atoi(levelStr)
	if err != nil || level < 1 || level > 4 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "level must be 1-4"})
		return
	}

	mod, err := h.registry.Build(moduleID, h.difficulty.Get())
	if err != nil {
		http.NotFound(w, r)
		return
	}

	hint := mod.Meta().Hints[level-1]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"level": level,
		"total": 4,
		"hint":  hint,
	})
}

func (h *Handler) renderPage(w http.ResponseWriter, name string, data PageData) {
	// First render the inner template
	var inner bytes.Buffer
	if err := h.renderer.Render(&inner, name, data); err != nil {
		h.logger.Error().Err(err).Str("template", name).Msg("template render failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Then wrap in layout
	data.Content = template.HTML(inner.String())
	if err := h.renderer.Render(w, "layout", data); err != nil {
		h.logger.Error().Err(err).Msg("layout render failed")
	}
}

// responseRecorder captures the response body while passing headers/status to the real writer.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	// Copy any headers set by the module (e.g., security headers)
	for k, vv := range r.Header() {
		for _, v := range vv {
			r.ResponseWriter.Header().Set(k, v)
		}
	}
}
