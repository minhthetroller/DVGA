package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DynamicConfig writes a Traefik file-provider dynamic configuration that
// maps per-user subdomains to the user's Fargate task private IP. Traefik
// watches the file and adds/removes routers accordingly.
type DynamicConfig struct {
	mu      sync.Mutex
	path    string
	routers map[string]string // username -> task IP
}

func NewDynamicConfig(path string) *DynamicConfig {
	return &DynamicConfig{
		path:    path,
		routers: make(map[string]string),
	}
}

func (d *DynamicConfig) Add(username, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routers[username] = ip
	d.flushLocked()
}

func (d *DynamicConfig) Remove(username string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.routers, username)
	d.flushLocked()
}

// flushLocked writes the full dynamic config from the current router map.
// Caller must hold d.mu. The file is written in place (the path is a
// single-file bind mount, so temp+rename would hit EXDEV). The file is
// tiny and Traefik's file provider tolerates transient parse failures by
// re-reading on the next watch event.
func (d *DynamicConfig) flushLocked() {
	if dir := filepath.Dir(d.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Printf("dynamic: mkdir %s: %v\n", dir, err)
			return
		}
	}

	dom := domain()
	var b []byte
	if len(d.routers) == 0 {
		// Empty file is the cleanest valid dynamic config for Traefik's
		// file provider (any "routers:" null map yields "routers cannot
		// be a standalone element"). Traefik treats a missing top-level
		// section as no routers/services.
		if err := os.WriteFile(d.path, b, 0o644); err != nil {
			fmt.Printf("dynamic: write %s: %v\n", d.path, err)
		}
		return
	}
	b = append(b, "http:\n"...)
	b = append(b, "  routers:\n"...)
	for user := range d.routers {
		b = append(b, fmt.Sprintf(
			"    %s:\n"+
				"      rule: \"Host(`%s.%s`)\"\n"+
				"      entryPoints:\n        - websecure\n"+
				"      service: %s\n"+
				"      tls:\n        certResolver: le\n",
			user, user, dom, user)...)
	}
	b = append(b, "  services:\n"...)
	for user, ip := range d.routers {
		b = append(b, fmt.Sprintf(
			"    %s:\n      loadBalancer:\n        servers:\n          - url: \"http://%s:4280\"\n",
			user, ip)...)
	}

	if err := os.WriteFile(d.path, b, 0o644); err != nil {
		fmt.Printf("dynamic: write %s: %v\n", d.path, err)
	}
}

// domain returns the configured domain from the process env.
func domain() string {
	return getEnv("DOMAIN", "dvga.online")
}
