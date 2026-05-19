package components

import "DVGA/internal/core"

// RegisterAll registers all Vulnerable and Outdated Components sub-vulnerabilities.
func RegisterAll(reg *core.Registry) {
	reg.Register("component-inventory", func(d core.Difficulty) core.VulnModule {
		return &ComponentsModule{difficulty: d, meta: componentInventoryMeta(d), serve: serveComponentInventory}
	})
	reg.Register("legacy-markdown", func(d core.Difficulty) core.VulnModule {
		return &ComponentsModule{difficulty: d, meta: legacyMarkdownMeta(d), serve: serveLegacyMarkdown}
	})
}
