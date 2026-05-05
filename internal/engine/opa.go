package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/outscale-srt20/osc-policy/internal/report"
)

// Engine encapsule le moteur OPA pour évaluer les policies.
type Engine struct {
	policies *LoadedPolicies
	catalog  map[string]interface{}
	debug    bool

	packages []string
	skip     map[string]bool
	profile  string
}

// Options de création du moteur.
type Options struct {
	Policies  *LoadedPolicies
	Catalog   map[string]interface{}
	Debug     bool
	SkipRules []string
	Profile   string
}

// New construit un nouveau moteur OPA.
func New(opts Options) (*Engine, error) {
	if opts.Policies == nil {
		return nil, fmt.Errorf("aucune policy chargée")
	}
	skip := map[string]bool{}
	for _, r := range opts.SkipRules {
		skip[r] = true
	}
	e := &Engine{
		policies: opts.Policies,
		catalog:  opts.Catalog,
		debug:    opts.Debug,
		skip:     skip,
		profile:  opts.Profile,
	}
	if err := e.discoverPackages(); err != nil {
		return nil, err
	}
	return e, nil
}

var pkgRe = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)`)

// discoverPackages parse chaque module pour trouver son package.
func (e *Engine) discoverPackages() error {
	seen := map[string]bool{}
	for path, src := range e.policies.Modules {
		m := pkgRe.FindStringSubmatch(src)
		if len(m) < 2 {
			return fmt.Errorf("pas de package dans %s", path)
		}
		pkg := m[1]
		if strings.HasSuffix(pkg, "_test") || strings.Contains(pkg, ".test") {
			continue
		}
		if strings.HasPrefix(pkg, "lib") {
			continue
		}
		if !e.packageMatchesProfile(pkg) {
			continue
		}
		if !seen[pkg] {
			e.packages = append(e.packages, pkg)
			seen[pkg] = true
		}
	}
	sort.Strings(e.packages)
	return nil
}

func (e *Engine) packageMatchesProfile(pkg string) bool {
	switch e.profile {
	case "", "all":
		return true
	case "security":
		return strings.HasPrefix(pkg, "security.")
	case "finops":
		return strings.HasPrefix(pkg, "finops.")
	case "compliance":
		return strings.HasPrefix(pkg, "compliance.")
	}
	return true
}

// Packages liste les packages Rego chargés.
func (e *Engine) Packages() []string { return e.packages }

// RuleCount compte les blocs metadata id:.
func (e *Engine) RuleCount() int {
	count := 0
	for _, src := range e.policies.Modules {
		count += strings.Count(src, "# id:")
	}
	if count == 0 {
		return len(e.packages)
	}
	return count
}

// Modules retourne les modules sous forme map (path → source).
func (e *Engine) Modules() map[string]string {
	out := map[string]string{}
	for k, v := range e.policies.Modules {
		out[k] = v
	}
	return out
}

// Evaluate exécute les règles `deny` pour chaque package sur l'input donné
// et construit des Findings à partir des JSON renvoyés.
func (e *Engine) Evaluate(ctx context.Context, input interface{}, source report.Source) ([]report.Finding, error) {
	store := inmem.NewFromObject(map[string]interface{}{
		"catalog": e.catalog,
	})

	moduleOpts := make([]func(*rego.Rego), 0, len(e.policies.Modules)+2)
	for path, src := range e.policies.Modules {
		moduleOpts = append(moduleOpts, rego.Module(path, src))
	}
	moduleOpts = append(moduleOpts, rego.Store(store))

	findings := []report.Finding{}

	for _, pkg := range e.packages {
		query := fmt.Sprintf("data.%s.deny", pkg)
		opts := append([]func(*rego.Rego){rego.Query(query), rego.Input(input)}, moduleOpts...)
		r := rego.New(opts...)
		rs, err := r.Eval(ctx)
		if err != nil {
			if e.debug {
				fmt.Printf("debug: erreur évaluation %s: %v\n", pkg, err)
			}
			return nil, fmt.Errorf("évaluation %s: %w", pkg, err)
		}
		for _, result := range rs {
			for _, expr := range result.Expressions {
				values, ok := expr.Value.([]interface{})
				if !ok {
					continue
				}
				for _, v := range values {
					f, err := parseDenyValue(v, source)
					if err != nil {
						if e.debug {
							fmt.Printf("debug: deny parse error: %v\n", err)
						}
						continue
					}
					if e.skip[f.RuleID] {
						continue
					}
					if f.Timestamp.IsZero() {
						f.Timestamp = time.Now()
					}
					if f.Status == "" {
						f.Status = "FAILED"
					}
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}

// parseDenyValue convertit la valeur retournée par un deny Rego (JSON string
// ou map) en Finding.
func parseDenyValue(v interface{}, source report.Source) (report.Finding, error) {
	var f report.Finding

	switch val := v.(type) {
	case string:
		if err := json.Unmarshal([]byte(val), &f); err != nil {
			return f, err
		}
	case map[string]interface{}:
		raw, err := json.Marshal(val)
		if err != nil {
			return f, err
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return f, err
		}
	default:
		return f, fmt.Errorf("type inattendu %T", v)
	}

	f.Source = source
	return f, nil
}
