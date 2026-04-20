package injection

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Injection sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("sqli", func(d core.Difficulty) core.VulnModule {
		return &InjectionModule{difficulty: d, meta: sqliMeta(d), serve: serveSQLi, store: store}
	})
	reg.Register("sqli-blind", func(d core.Difficulty) core.VulnModule {
		return &InjectionModule{difficulty: d, meta: sqliBlindMeta(d), serve: serveSQLiBlind, store: store}
	})
	reg.Register("cmdi", func(d core.Difficulty) core.VulnModule {
		return &InjectionModule{difficulty: d, meta: cmdiMeta(d), serve: serveCmdI}
	})
	reg.Register("xss-reflected", func(d core.Difficulty) core.VulnModule {
		return &InjectionModule{difficulty: d, meta: xssReflectedMeta(d), serve: serveXSSReflected, store: store}
	})
	reg.Register("xss-stored", func(d core.Difficulty) core.VulnModule {
		return &InjectionModule{difficulty: d, meta: xssStoredMeta(d), serve: serveXSSStored, store: store}
	})
}

