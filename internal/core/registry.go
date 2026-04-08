package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds module factories keyed by module ID.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]ModuleFactory
}

func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]ModuleFactory)}
}

// Register adds a factory under the given module ID.
func (r *Registry) Register(id string, f ModuleFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[id] = f
}

// Build creates a single module by ID for the given difficulty.
func (r *Registry) Build(id string, d Difficulty) (VulnModule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[id]
	if !ok {
		return nil, fmt.Errorf("module %q not registered", id)
	}
	return f.Create(d), nil
}

// All builds every registered module for the given difficulty.
func (r *Registry) All(d Difficulty) []VulnModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	modules := make([]VulnModule, 0, len(r.factories))
	for _, f := range r.factories {
		modules = append(modules, f.Create(d))
	}
	return modules
}

// IDs returns all registered module IDs in sorted order.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.factories))
	for id := range r.factories {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Categories builds all modules for the given difficulty and groups them by category.
func (r *Registry) Categories(d Difficulty) map[string][]VulnModule {
	modules := r.All(d)
	cats := make(map[string][]VulnModule)
	for _, m := range modules {
		cat := m.Meta().Category
		cats[cat] = append(cats[cat], m)
	}
	return cats
}
