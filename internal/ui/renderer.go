package ui

import (
	"html/template"
	"io"
	"path/filepath"
)

// TemplateRenderer loads and renders HTML templates.
type TemplateRenderer struct {
	templates *template.Template
}

// PageData is the data passed to every template.
type PageData struct {
	PageTitle  string
	Username   string
	Difficulty string
	ActiveID   string
	Sidebar    []SidebarCategory
	Content    template.HTML
	MoreInfo   []string
}

// SidebarCategory groups module links by OWASP category.
type SidebarCategory struct {
	Name  string
	Items []SidebarItem
}

// SidebarItem is a single sidebar nav link.
type SidebarItem struct {
	ID   string
	Name string
	URL  string
}

func NewRenderer(templatesDir string) (*TemplateRenderer, error) {
	pattern := filepath.Join(templatesDir, "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		return nil, err
	}
	return &TemplateRenderer{templates: tmpl}, nil
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data PageData) error {
	return r.templates.ExecuteTemplate(w, name, data)
}
