package crypto

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Cryptographic Failures sub-vulnerability factories.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("data-exposure", &DataExposureFactory{store: store})
	reg.Register("weak-passwd", &WeakPasswdFactory{store: store})
}
