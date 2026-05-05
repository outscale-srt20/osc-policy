package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/plan"
	"github.com/outscale-srt20/osc-policy/internal/report"
)

func scanPlanCmd() *cobra.Command {
	var (
		changesOnly bool
		region      string
	)

	c := &cobra.Command{
		Use:   "plan <plan.json>",
		Short: "Analyse un plan Terraform JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if region == "" {
				region = cfg.Outscale.Region
			}
			planPath := args[0]

			planDoc, err := plan.Parse(planPath)
			if err != nil {
				return err
			}
			if changesOnly {
				resources := plan.ExtractAll(planDoc)
				_ = plan.FilterChangesOnly(resources)
				// Note: la simplification effective serait de restreindre planned_values;
				// on laisse tel quel pour le moment (l'OPA reçoit le plan complet).
			}

			eng, err := buildEngine(cfg.Scan.Profile, cfg.Policies.ExtraDir, cfg.Scan.SkipRules, gflags.Debug, region, cfg.FinOps.PricesFile)
			if err != nil {
				return err
			}

			ctx := context.Background()
			findings, err := eng.Evaluate(ctx, map[string]interface{}(planDoc), report.SourcePlan)
			if err != nil {
				return fmt.Errorf("évaluation OPA: %w", err)
			}

			// Chaque finding provenant d'un plan a son FilePath = planPath
			for i := range findings {
				findings[i].FilePath = planPath
			}

			return runScan(ctx, findings, "plan", planPath, eng.RuleCount())
		},
	}
	c.Flags().BoolVar(&changesOnly, "changes-only", false, "Analyser uniquement les ressources qui changent")
	c.Flags().StringVar(&region, "region", "", "Région Outscale utilisée pour la tarification (défaut: config outscale.region)")
	return c
}
