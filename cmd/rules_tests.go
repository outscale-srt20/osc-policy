package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/catalog"
	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
)

func rulesTestCmd() *cobra.Command {
	var (
		verbose  bool
		coverage bool
	)

	c := &cobra.Command{
		Use:   "test",
		Short: "Exécuter opa test sur les policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			embedded, err := engine.LoadEmbedded()
			if err != nil {
				return err
			}
			eng, err := engine.New(engine.Options{Policies: embedded})
			if err != nil {
				return err
			}

			res, err := eng.RunTests(context.Background())
			if err != nil {
				return err
			}

			if verbose {
				for _, r := range res.Results {
					status := "PASS"
					if r.Error != nil {
						status = "ERROR"
					} else if !r.Pass() {
						status = "FAIL"
					}
					fmt.Printf("[%s] %s.%s\n", status, r.Package, r.Name)
				}
			}

			fmt.Printf("\n%d passed, %d failed, %d errors\n", res.Passed, res.Failed, res.Errors)
			if res.Failed > 0 || res.Errors > 0 {
				return fmt.Errorf("tests échoués")
			}

			// Valider les codes de conformité référencés par les règles.
			complianceProblems, err := validateRulesCompliance(embedded)
			if err != nil {
				return err
			}
			if len(complianceProblems) > 0 {
				fmt.Printf("\n%d problème(s) de conformité :\n", len(complianceProblems))
				for _, p := range complianceProblems {
					fmt.Printf("  ✗ %s\n", p)
				}
				return fmt.Errorf("validation compliance échouée")
			}
			fmt.Println("Compliance: tous les codes référencés sont valides.")

			_ = coverage
			return nil
		},
	}
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "Afficher chaque test")
	c.Flags().BoolVar(&coverage, "coverage", false, "Afficher le coverage")
	return c
}

// validateRulesCompliance parcourt toutes les règles embarquées, lit leurs
// métadonnées, et vérifie que chaque code framework + contrôle référencé
// dans le champ compliance: existe bien dans le catalogue de frameworks.
func validateRulesCompliance(bundle *engine.LoadedPolicies) ([]string, error) {
	frameworks, err := catalog.LoadFrameworks("")
	if err != nil {
		return nil, fmt.Errorf("chargement frameworks: %w", err)
	}

	var problems []string
	for path, src := range bundle.Modules {
		if strings.HasSuffix(path, "_test.rego") {
			continue
		}
		meta, err := docgen.ParseRegoMetadata(path, src)
		if err != nil || meta == nil {
			continue
		}
		if len(meta.Compliance) == 0 {
			continue
		}
		for _, p := range frameworks.ValidateCompliance(meta.Compliance) {
			problems = append(problems, fmt.Sprintf("%s — %s", meta.ID, p))
		}
	}
	return problems, nil
}
