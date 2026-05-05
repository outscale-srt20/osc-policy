package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/collector"
	"github.com/outscale-srt20/osc-policy/internal/config"
	"github.com/outscale-srt20/osc-policy/internal/report"
)

// scanTarget décrit une cible à scanner (credentials + région + label).
type scanTarget struct {
	Label  string // ex: "profil=secnumcloud" ou "env" ou "flags"
	Region string
	Client *collector.Client
}

func scanLiveCmd() *cobra.Command {
	var (
		region         string
		accessKey      string
		secretKey      string
		profileName    string
		snapshotOutput string
		snapshotInput  string
		collectors     []string
		compare        string
	)

	c := &cobra.Command{
		Use:   "live",
		Short: "Scanner les ressources live via l'API Outscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Mode offline: lecture d'un snapshot → scan mono-cible sans credentials
			if snapshotInput != "" {
				return runLiveFromSnapshot(cfg, snapshotInput, snapshotOutput, compare)
			}

			targets, err := resolveTargets(cfg, region, accessKey, secretKey, profileName)
			if err != nil {
				return err
			}

			if snapshotOutput != "" && len(targets) > 1 {
				return fmt.Errorf("--snapshot-output incompatible avec un scan multi-profils ; précisez --profile-name <nom>")
			}

			var allFindings []report.Finding
			var sources []string
			totalRules := 0
			var mergedSnapshot collector.Snapshot

			for i, t := range targets {
				if len(targets) > 1 {
					fmt.Fprintf(os.Stderr, "\n→ [%d/%d] %s (région %s)\n", i+1, len(targets), t.Label, t.Region)
				}

				snapshot := collector.Snapshot{Region: t.Region}
				cols := collector.Registry(collectors)
				bar := newCollectBar(t.Label, len(cols))
				for _, col := range cols {
					bar.Describe(fmt.Sprintf("  Collecte %-18s", col.Name()))
					resources, err := col.Collect(t.Client.AuthCtx, t.Client.API)
					if err != nil {
						snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("%s: %v", col.Name(), err))
						fmt.Fprintf(os.Stderr, "\n  ⚠ collector %s: %v\n", col.Name(), err)
					} else {
						snapshot.Resources = append(snapshot.Resources, resources...)
					}
					_ = bar.Add(1)
				}
				_ = bar.Finish()
				fmt.Fprintln(os.Stderr)

				if snapshotOutput != "" {
					data, _ := json.MarshalIndent(snapshot, "", "  ")
					if err := os.WriteFile(snapshotOutput, data, 0644); err != nil {
						return fmt.Errorf("écriture snapshot: %w", err)
					}
				}

				if compare != "" {
					if prev, err := loadSnapshot(compare); err == nil {
						for _, d := range computeDrift(prev, snapshot) {
							fmt.Fprintln(os.Stderr, d)
						}
					}
				}

				eng, err := buildEngine(cfg.Scan.Profile, cfg.Policies.ExtraDir, cfg.Scan.SkipRules, gflags.Debug, t.Region, cfg.FinOps.PricesFile)
				if err != nil {
					return err
				}
				totalRules = eng.RuleCount()

				ctx := context.Background()
				input := map[string]interface{}{
					"resources": snapshotToInput(snapshot),
					"region":    t.Region,
				}
				findings, err := eng.Evaluate(ctx, input, report.SourceLive)
				if err != nil {
					return fmt.Errorf("évaluation OPA (%s): %w", t.Label, err)
				}
				accountLabel := strings.TrimPrefix(t.Label, "profil=")
				for i := range findings {
					findings[i].Region = t.Region
					findings[i].Account = accountLabel
				}

				allFindings = append(allFindings, findings...)
				sources = append(sources, t.Region)
				mergedSnapshot.Resources = append(mergedSnapshot.Resources, snapshot.Resources...)
				mergedSnapshot.Errors = append(mergedSnapshot.Errors, snapshot.Errors...)
			}

			sourceLabel := "live:" + strings.Join(uniqueSorted(sources), "+")
			return runScan(context.Background(), allFindings, "live", sourceLabel, totalRules)
		},
	}

	c.Flags().StringVar(&region, "region", "", "Région Outscale")
	c.Flags().StringVar(&accessKey, "access-key", "", "Access Key ID")
	c.Flags().StringVar(&secretKey, "secret-key", "", "Secret Key")
	c.Flags().StringVar(&profileName, "profile-name", "", "Profil ~/.osc/config.json (vide = \"default\", \"all\" = tous les profils)")
	c.Flags().StringVar(&snapshotOutput, "snapshot-output", "", "Fichier de sortie snapshot JSON (incompatible multi-profils)")
	c.Flags().StringVar(&snapshotInput, "snapshot-input", "", "Utiliser un snapshot JSON existant")
	c.Flags().StringSliceVar(&collectors, "collectors", []string{"all"}, "Liste de collectors")
	c.Flags().StringVar(&compare, "compare", "", "Comparer avec un snapshot précédent")

	return c
}

// resolveTargets construit la liste des cibles à scanner selon la précédence :
//   1. --access-key / --secret-key → un seul scan
//   2. OUTSCALE_ACCESSKEYID env → un seul scan
//   3. --profile-name all → tous les profils de ~/.osc/config.json (opt-in)
//   4. --profile-name <nom> → ce profil
//   5. Sinon → profil "default" de ~/.osc/config.json
//   6. Si le fichier n'existe pas → fallback NewClient (erreur si pas de creds)
func resolveTargets(cfg *config.Config, region, accessKey, secretKey, profileName string) ([]scanTarget, error) {
	// Cas 1 — flags explicites
	if accessKey != "" && secretKey != "" {
		if region == "" {
			region = cfg.Outscale.Region
		}
		client, err := collector.NewClient(region, accessKey, secretKey, "")
		if err != nil {
			return nil, err
		}
		return []scanTarget{{Label: "flags", Region: client.Region, Client: client}}, nil
	}

	// Cas 2 — env vars explicites
	if os.Getenv("OUTSCALE_ACCESSKEYID") != "" && os.Getenv("OUTSCALE_SECRETKEYID") != "" {
		client, err := collector.NewClient(region, "", "", "")
		if err != nil {
			return nil, err
		}
		return []scanTarget{{Label: "env", Region: client.Region, Client: client}}, nil
	}

	// Cas 3 — --profile-name all : itération explicite sur tous les profils
	if profileName == "all" {
		all, err := collector.LoadAllOSCProfiles()
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("aucun ~/.osc/config.json trouvé ou vide")
		}
		names := make([]string, 0, len(all))
		for n := range all {
			names = append(names, n)
		}
		sort.Strings(names)
		targets := make([]scanTarget, 0, len(names))
		for _, n := range names {
			client, err := collector.NewClientFromProfile(all[n])
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ profil %q ignoré: %v\n", n, err)
				continue
			}
			targets = append(targets, scanTarget{Label: "profil=" + n, Region: client.Region, Client: client})
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("aucun profil exploitable dans ~/.osc/config.json")
		}
		return targets, nil
	}

	// Cas 4 & 5 — profil explicite ou "default" implicite
	effective := profileName
	if effective == "" {
		effective = "default"
	}
	prof, err := collector.LoadOSCProfile(effective)
	if err != nil {
		return nil, err
	}
	if prof != nil {
		client, err := collector.NewClientFromProfile(*prof)
		if err != nil {
			return nil, fmt.Errorf("profil %q: %w", effective, err)
		}
		return []scanTarget{{Label: "profil=" + effective, Region: client.Region, Client: client}}, nil
	}

	// Cas 6 — fallback, laissera NewClient renvoyer l'erreur "creds introuvables"
	client, err := collector.NewClient(region, "", "", "")
	if err != nil {
		return nil, err
	}
	return []scanTarget{{Label: "default", Region: client.Region, Client: client}}, nil
}

func newCollectBar(label string, total int) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(24),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "",
			BarEnd:        "",
		}),
		progressbar.OptionSetDescription(fmt.Sprintf("  %s", label)),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionClearOnFinish(),
	)
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func runLiveFromSnapshot(cfg *config.Config, snapshotInput, snapshotOutput, compare string) error {
	data, err := os.ReadFile(snapshotInput)
	if err != nil {
		return fmt.Errorf("lecture snapshot: %w", err)
	}
	var snapshot collector.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("parse snapshot: %w", err)
	}

	if snapshotOutput != "" {
		data, _ := json.MarshalIndent(snapshot, "", "  ")
		if err := os.WriteFile(snapshotOutput, data, 0644); err != nil {
			return fmt.Errorf("écriture snapshot: %w", err)
		}
	}
	if compare != "" {
		if prev, err := loadSnapshot(compare); err == nil {
			for _, d := range computeDrift(prev, snapshot) {
				fmt.Fprintln(os.Stderr, d)
			}
		}
	}

	activeRegion := snapshot.Region
	if activeRegion == "" {
		activeRegion = cfg.Outscale.Region
	}
	eng, err := buildEngine(cfg.Scan.Profile, cfg.Policies.ExtraDir, cfg.Scan.SkipRules, gflags.Debug, activeRegion, cfg.FinOps.PricesFile)
	if err != nil {
		return err
	}
	ctx := context.Background()
	input := map[string]interface{}{
		"resources": snapshotToInput(snapshot),
		"region":    snapshot.Region,
	}
	findings, err := eng.Evaluate(ctx, input, report.SourceLive)
	if err != nil {
		return fmt.Errorf("évaluation OPA: %w", err)
	}
	for i := range findings {
		findings[i].Region = snapshot.Region
	}
	return runScan(ctx, findings, "live", "live:"+snapshot.Region, eng.RuleCount())
}

func snapshotToInput(s collector.Snapshot) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(s.Resources))
	for _, r := range s.Resources {
		out = append(out, map[string]interface{}{
			"type":    r.Type,
			"id":      r.ID,
			"address": r.Address,
			"values":  r.Values,
		})
	}
	return out
}

func loadSnapshot(path string) (collector.Snapshot, error) {
	var s collector.Snapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

func computeDrift(prev, curr collector.Snapshot) []string {
	prevByID := map[string]bool{}
	for _, r := range prev.Resources {
		prevByID[r.ID] = true
	}
	currByID := map[string]bool{}
	for _, r := range curr.Resources {
		currByID[r.ID] = true
	}
	var drift []string
	for id := range currByID {
		if !prevByID[id] {
			drift = append(drift, "+ nouveau: "+id)
		}
	}
	for id := range prevByID {
		if !currByID[id] {
			drift = append(drift, "- supprimé: "+id)
		}
	}
	return drift
}
