package engine

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/tester"
)

// TestResult résume l'exécution d'opa test.
type TestResult struct {
	Passed  int
	Failed  int
	Errors  int
	Results []*tester.Result
}

// RunTests exécute `opa test` sur les policies chargées.
func (e *Engine) RunTests(ctx context.Context) (*TestResult, error) {
	modules := map[string]*ast.Module{}
	for path, src := range e.policies.Modules {
		m, err := ast.ParseModule(path, src)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		modules[path] = m
	}

	runner := tester.NewRunner().SetModules(modules)

	ch, err := runner.RunTests(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("tests runner: %w", err)
	}

	res := &TestResult{}
	for r := range ch {
		res.Results = append(res.Results, r)
		if r.Error != nil {
			res.Errors++
			continue
		}
		if r.Pass() {
			res.Passed++
		} else {
			res.Failed++
		}
	}
	return res, nil
}
