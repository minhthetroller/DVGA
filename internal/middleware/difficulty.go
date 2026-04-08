package middleware

import (
	"net/http"

	"DVGA/internal/core"

	"github.com/rs/zerolog"
)

// DifficultyDecorator logs the active difficulty for each request.
type DifficultyDecorator struct {
	Logger     zerolog.Logger
	Difficulty *core.SafeDifficulty
}

func (dd *DifficultyDecorator) Wrap(inner core.VulnModule) core.VulnModule {
	return &difficultyModule{inner: inner, logger: dd.Logger, difficulty: dd.Difficulty}
}

type difficultyModule struct {
	inner      core.VulnModule
	logger     zerolog.Logger
	difficulty *core.SafeDifficulty
}

func (m *difficultyModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.logger.Debug().
		Str("module", m.inner.Meta().ID).
		Str("difficulty", m.difficulty.Get().String()).
		Msg("difficulty check")
	m.inner.ServeHTTP(w, r)
}

func (m *difficultyModule) Meta() core.ModuleMeta {
	return m.inner.Meta()
}
