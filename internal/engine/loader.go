package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	policies "github.com/outscale-srt20/osc-policy/policies"
)

// LoadedPolicies contient les fichiers .rego (path → contenu).
type LoadedPolicies struct {
	Modules map[string]string
}

// LoadEmbedded charge les policies embarquées dans le binaire.
func LoadEmbedded() (*LoadedPolicies, error) {
	modules := map[string]string{}
	err := fs.WalkDir(policies.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		data, err := policies.FS.ReadFile(path)
		if err != nil {
			return err
		}
		modules["embed://"+path] = string(data)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chargement policies embarquées: %w", err)
	}
	return &LoadedPolicies{Modules: modules}, nil
}

// LoadFromDir charge les policies .rego depuis un répertoire (récursif).
func LoadFromDir(dir string) (*LoadedPolicies, error) {
	modules := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		modules[path] = string(data)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chargement policies %s: %w", dir, err)
	}
	return &LoadedPolicies{Modules: modules}, nil
}

// Merge fusionne deux sets de policies (b prime sur a en cas de conflit).
func Merge(a, b *LoadedPolicies) *LoadedPolicies {
	out := &LoadedPolicies{Modules: map[string]string{}}
	for k, v := range a.Modules {
		out.Modules[k] = v
	}
	for k, v := range b.Modules {
		out.Modules[k] = v
	}
	return out
}
