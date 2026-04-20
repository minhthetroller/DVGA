package core

import "net/http"

// ModuleKind indicates whether a module presents a web or API surface.
type ModuleKind int

const (
	KindWeb ModuleKind = iota
	KindAPI
)

// VulnModule is the interface every vulnerability module implements.
type VulnModule interface {
	http.Handler
	Meta() ModuleMeta
}

// APIModule extends VulnModule with a JSON API surface.
type APIModule interface {
	VulnModule
	APIRoutes() []APIRouteSpec
	ServeAPI(w http.ResponseWriter, r *http.Request)
}

// APIRouteSpec describes a single API endpoint exposed by an APIModule.
type APIRouteSpec struct {
	Method string
	Path   string
}

// ModuleConstructor is a function that builds a VulnModule for the given
// difficulty. It replaces the old ModuleFactory interface.
type ModuleConstructor func(d Difficulty) VulnModule

// ModuleMeta holds metadata about a vulnerability module.
type ModuleMeta struct {
	ID          string
	Name        string
	Description string
	Category    string
	Kind        ModuleKind
	Difficulty  Difficulty
	References  []string
	Hints       [4]string
}

// MiddlewareDecorator wraps a VulnModule with cross-cutting behaviour.
type MiddlewareDecorator interface {
	Wrap(inner VulnModule) VulnModule
}
