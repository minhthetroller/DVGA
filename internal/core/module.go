package core

import "net/http"

// VulnModule is the interface every vulnerability module implements.
type VulnModule interface {
	http.Handler
	Meta() ModuleMeta
}

// ModuleMeta holds metadata about a vulnerability module.
type ModuleMeta struct {
	ID          string
	Name        string
	Description string
	Category    string
	Difficulty  Difficulty
	References  []string
	Hints       [4]string
}

// ModuleFactory creates VulnModule instances for a given difficulty.
type ModuleFactory interface {
	Create(d Difficulty) VulnModule
}

// MiddlewareDecorator wraps a VulnModule with cross-cutting behaviour.
type MiddlewareDecorator interface {
	Wrap(inner VulnModule) VulnModule
}
