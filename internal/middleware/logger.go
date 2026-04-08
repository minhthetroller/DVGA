package middleware

import (
	"net/http"
	"time"

	"DVGA/internal/core"

	"github.com/rs/zerolog"
)

// LoggerDecorator wraps a VulnModule with request logging.
type LoggerDecorator struct {
	Logger zerolog.Logger
}

func (ld *LoggerDecorator) Wrap(inner core.VulnModule) core.VulnModule {
	return &loggedModule{inner: inner, logger: ld.Logger}
}

type loggedModule struct {
	inner  core.VulnModule
	logger zerolog.Logger
}

func (m *loggedModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	meta := m.inner.Meta()
	m.inner.ServeHTTP(w, r)
	m.logger.Info().
		Str("module", meta.ID).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Dur("duration", time.Since(start)).
		Msg("module request")
}

func (m *loggedModule) Meta() core.ModuleMeta {
	return m.inner.Meta()
}
