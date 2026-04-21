package misconfig

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Security Misconfiguration sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("debug-info", func(d core.Difficulty) core.VulnModule {
		return &MisconfigModule{difficulty: d, meta: debugInfoMeta(d), serve: serveDebugInfo, store: store}
	})
	reg.Register("security-headers", func(d core.Difficulty) core.VulnModule {
		return &MisconfigModule{difficulty: d, meta: securityHeadersMeta(d), serve: serveSecurityHeaders}
	})
}

