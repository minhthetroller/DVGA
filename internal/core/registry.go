package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds module constructors keyed by module ID.
type Registry struct {
	mu           sync.RWMutex
	constructors map[string]ModuleConstructor
}

func NewRegistry() *Registry {
	return &Registry{constructors: make(map[string]ModuleConstructor)}
}

// Register adds a constructor under the given module ID.
func (r *Registry) Register(id string, c ModuleConstructor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.constructors[id] = c
}

// Build creates a single module by ID for the given difficulty.
func (r *Registry) Build(id string, d Difficulty) (VulnModule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.constructors[id]
	if !ok {
		return nil, fmt.Errorf("module %q not registered", id)
	}
	return c(d), nil
}

// All builds every registered module for the given difficulty.
func (r *Registry) All(d Difficulty) []VulnModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	modules := make([]VulnModule, 0, len(r.constructors))
	for _, c := range r.constructors {
		modules = append(modules, c(d))
	}
	return modules
}

// IDs returns all registered module IDs in sorted order.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.constructors))
	for id := range r.constructors {
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
