// Package app wires together all modules, middleware, and the HTTP router to build the DVGA server.
package app

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/middleware"
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
	"DVGA/internal/ui"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
	"github.com/rs/zerolog"
)

type App struct {
	Store      *database.Store
	Sessions   *session.Manager
	Registry   *core.Registry
	Chain      *core.Chain
	Difficulty *core.SafeDifficulty
	Handler    *ui.Handler
	Logger     zerolog.Logger
	Server     *http.Server
}

func New(dbPath, templatesDir, staticDir string) (*App, error) {
	// Zerolog — pretty console output for development
	logger := zerolog.New(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	).With().Timestamp().Caller().Logger()

	// Database
	store, err := database.NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	if err := store.AutoMigrate(); err != nil {
		return nil, err
	}
	if err := store.Seed(); err != nil {
		logger.Warn().Err(err).Msg("seed skipped (data may already exist)")
	}

	// Create data/files directory for path traversal module
	os.MkdirAll("./data/files", 0755)

	// Session manager
	sessions := session.NewManager()
	sessions.StartCleanup(5*time.Minute, 30*time.Minute, time.Hour)

	// Difficulty (thread-safe)
	difficulty := core.NewSafeDifficulty(core.Easy)

	// Module registry
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

	// Decorator chain
	chain := core.NewChain()
	chain.Use(&middleware.LoggerDecorator{Logger: logger})
	chain.Use(&middleware.DifficultyDecorator{Logger: logger, Difficulty: difficulty})

	// Template renderer
	renderer, err := ui.NewRenderer(templatesDir)
	if err != nil {
		return nil, err
	}

	// UI handler
	handler := ui.NewHandler(renderer, registry, chain, store, sessions, difficulty, staticDir, logger)

	return &App{
		Store:      store,
		Sessions:   sessions,
		Registry:   registry,
		Chain:      chain,
		Difficulty: difficulty,
		Handler:    handler,
		Logger:     logger,
	}, nil
}

func (a *App) ListenAndServe(addr string) error {
	// Root chi router with observability middleware
	root := chi.NewRouter()

	// HTTP request logger (httplog integrates with zerolog)
	httpLogger := httplog.NewLogger("dvga", httplog.Options{
		LogLevel: slog.LevelInfo,
		Concise:  true,
	})
	root.Use(httplog.RequestLogger(httpLogger))

	// Recover from panics and log a stack trace instead of crashing
	root.Use(chimw.Recoverer)

	// Mount the app routes
	root.Mount("/", a.Handler.Routes())

	a.Logger.Info().Str("addr", addr).Msg("DVGA starting")

	srv := &http.Server{
		Addr:         addr,
		Handler:      root,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	a.Server = srv
	return srv.ListenAndServe()
}
