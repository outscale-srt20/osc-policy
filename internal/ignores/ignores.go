// Package ignores gère les suppressions de findings via un fichier
// .osc-policy-ignore versionné en Git. Chaque suppression doit avoir une
// raison et idéalement une date d'expiration.
package ignores

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultPath = ".osc-policy-ignore"

// Ignore représente une entrée du fichier de suppressions.
type Ignore struct {
	Rule     string `yaml:"rule"`
	Resource string `yaml:"resource"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires,omitempty"`
	AddedBy  string `yaml:"added_by,omitempty"`
	AddedAt  string `yaml:"added_at,omitempty"`
}

// File est la racine du fichier YAML.
type File struct {
	Ignores []Ignore `yaml:"ignores"`
}

// Load lit le fichier d'ignores. Retourne un File vide si le fichier
// n'existe pas (comportement optionnel).
func Load(path string) (*File, error) {
	if path == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("lecture %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

// Save écrit le fichier d'ignores avec un commentaire d'en-tête.
func Save(path string, f *File) error {
	if path == "" {
		path = DefaultPath
	}
	out := "# osc-policy suppressions\n"
	out += "# Chaque entrée doit avoir une raison et idéalement une date d'expiration.\n"
	out += "# Versionner ce fichier en Git, revue obligatoire en MR.\n\n"
	body, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	out += string(body)
	return os.WriteFile(path, []byte(out), 0644)
}

// Match teste si une combinaison (rule, resource) est ignorée et toujours
// valide (non expirée).
func (f *File) Match(rule, resource string) (*Ignore, bool) {
	now := time.Now()
	for i := range f.Ignores {
		ig := &f.Ignores[i]
		if !strings.EqualFold(ig.Rule, rule) {
			continue
		}
		if ig.Resource != "" && ig.Resource != "*" && ig.Resource != resource {
			continue
		}
		if ig.Expires != "" {
			t, err := time.Parse("2006-01-02", ig.Expires)
			if err == nil && now.After(t) {
				continue // expiré
			}
		}
		return ig, true
	}
	return nil, false
}

// Add ajoute (ou met à jour) une entrée.
func (f *File) Add(ig Ignore) {
	for i := range f.Ignores {
		existing := &f.Ignores[i]
		if strings.EqualFold(existing.Rule, ig.Rule) && existing.Resource == ig.Resource {
			f.Ignores[i] = ig
			return
		}
	}
	f.Ignores = append(f.Ignores, ig)
}
