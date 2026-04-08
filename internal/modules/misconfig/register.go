package misconfig

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Security Misconfiguration sub-vulnerability factories.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("debug-info", &DebugInfoFactory{store: store})
	reg.Register("security-headers", &HeadersFactory{})
}
