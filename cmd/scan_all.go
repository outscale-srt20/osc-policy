package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/collector"
	"github.com/outscale-srt20/osc-policy/internal/plan"
	"github.com/outscale-srt20/osc-policy/internal/report"
)

func scanAllCmd() *cobra.Command {
	var (
		region      string
		accessKey   string
		secretKey   string
		profileName string
	)

	c := &cobra.Command{
		Use:   "all <plan.json>",
		Short: "Scan plan + live combiné",
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

			eng, err := buildEngine(cfg.Scan.Profile, cfg.Policies.ExtraDir, cfg.Scan.SkipRules, gflags.Debug, region, cfg.FinOps.PricesFile)
			if err != nil {
				return err
			}
			ctx := context.Background()

			// Plan
			planDoc, err := plan.Parse(planPath)
			if err != nil {
				return err
			}
			planFindings, err := eng.Evaluate(ctx, map[string]interface{}(planDoc), report.SourcePlan)
			if err != nil {
				return fmt.Errorf("plan: %w", err)
			}
			for i := range planFindings {
				planFindings[i].FilePath = planPath
			}

			// Live
			client, err := collector.NewClient(region, accessKey, secretKey, profileName)
			if err != nil {
				return err
			}
			snapshot := collector.Snapshot{Region: client.Region}
			for _, col := range collector.Registry(nil) {
				res, err := col.Collect(client.AuthCtx, client.API)
				if err != nil {
					fmt.Printf("⚠ collector %s: %v\n", col.Name(), err)
					continue
				}
				snapshot.Resources = append(snapshot.Resources, res...)
			}
			liveInput := map[string]interface{}{
				"resources": snapshotToInput(snapshot),
				"region":    snapshot.Region,
			}
			liveFindings, err := eng.Evaluate(ctx, liveInput, report.SourceLive)
			if err != nil {
				return fmt.Errorf("live: %w", err)
			}
			for i := range liveFindings {
				liveFindings[i].Region = snapshot.Region
			}

			// Fusion + dédup simple (par rule_id + resource_address)
			seen := map[string]bool{}
			var findings []report.Finding
			for _, f := range append(planFindings, liveFindings...) {
				key := f.RuleID + "|" + f.ResourceAddress
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, f)
			}

			return runScan(ctx, findings, "all", planPath, eng.RuleCount())
		},
	}

	c.Flags().StringVar(&region, "region", "", "Région Outscale")
	c.Flags().StringVar(&accessKey, "access-key", "", "Access Key ID")
	c.Flags().StringVar(&secretKey, "secret-key", "", "Secret Key")
	c.Flags().StringVar(&profileName, "profile-name", "", "Nom du profil à charger dans ~/.osc/config.json (ou env OSC_PROFILE)")
	return c
}
