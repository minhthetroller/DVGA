package injection

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Injection sub-vulnerability factories.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("sqli", &SQLiFactory{store: store})
	reg.Register("sqli-blind", &SQLiBlindFactory{store: store})
	reg.Register("cmdi", &CmdInjFactory{})
	reg.Register("xss-reflected", &XSSReflectedFactory{store: store})
	reg.Register("xss-stored", &XSSStoredFactory{store: store})
}
