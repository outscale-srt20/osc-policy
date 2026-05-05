package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/catalog"
	"github.com/outscale-srt20/osc-policy/internal/engine"
	"github.com/outscale-srt20/osc-policy/internal/ignores"
	"github.com/outscale-srt20/osc-policy/internal/report"
	"github.com/outscale-srt20/osc-policy/version"
)

func scanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scanner des ressources Outscale (plan ou live)",
		// Le banner ASCII s'affiche dès l'invocation d'une sous-commande scan,
		// avant toute collecte / évaluation OPA. Écrit sur stderr pour ne pas
		// polluer un stdout capturé (ex: JSON/SARIF redirigé vers un fichier).
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			report.WriteStartupBanner(os.Stderr, version.Version, gflags.NoColor, gflags.Quiet)
		},
	}
	c.AddCommand(scanPlanCmd())
	c.AddCommand(scanLiveCmd())
	c.AddCommand(scanAllCmd())
	return c
}

// buildEngine initialise le moteur OPA (policies embed + policies extra).
// La région active est utilisée pour sélectionner la grille tarifaire injectée
// dans data.catalog.
func buildEngine(profile, extraDir string, skipRules []string, debug bool, region, pricesFile string) (*engine.Engine, error) {
	embedded, err := engine.LoadEmbedded()
	if err != nil {
		return nil, err
	}
	policies := embedded
	if extraDir != "" {
		extra, err := engine.LoadFromDir(extraDir)
		if err != nil {
			return nil, err
		}
		policies = engine.Merge(embedded, extra)
	}
	prices, err := catalog.Load(pricesFile)
	if err != nil {
		return nil, err
	}
	return engine.New(engine.Options{
		Policies:  policies,
		Catalog:   prices.AsData(region),
		Debug:     debug,
		SkipRules: skipRules,
		Profile:   profile,
	})
}

// writeReport écrit le résultat au format demandé.
func writeReport(w io.Writer, result report.ScanResult, format, profile, input string, noColor, quiet bool, ruleCount int) error {
	switch format {
	case "json":
		return report.WriteJSON(w, result)
	case "sarif":
		return report.WriteSARIF(w, result, "https://github.com/outscale-srt20/osc-policy")
	case "junit":
		return report.WriteJUnit(w, result)
	case "markdown":
		return report.WriteMarkdown(w, result)
	case "terminal", "":
		report.WriteTerminal(w, result, report.TerminalOptions{
			NoColor:   noColor,
			Quiet:     quiet,
			ToolName:  "osc-policy",
			Version:   version.Version,
			Profile:   profile,
			Account:   accountsLabel(result.Findings),
			Input:     input,
			RuleCount: ruleCount,
		})
		return nil
	}
	return fmt.Errorf("format non supporté: %s", format)
}

// accountsLabel regroupe les comptes distincts tagués sur les findings.
// Retourne une chaîne vide si aucun finding ne porte de compte (mode plan).
func accountsLabel(findings []report.Finding) string {
	seen := map[string]bool{}
	var names []string
	for _, f := range findings {
		if f.Account == "" || seen[f.Account] {
			continue
		}
		seen[f.Account] = true
		names = append(names, f.Account)
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		return strings.Join(names, " + ")
	}
}

// computeExitCode détermine le code de sortie selon fail-on et min-grade.
// fail-on : exit 1 si au moins un finding FAILED atteint la sévérité seuil.
// min-grade : exit 1 si le grade calculé est pire que le seuil (ex. min=B, got=D).
// Les deux sont combinés par OU logique ; si aucun n'est renseigné, exit 0.
func computeExitCode(findings []report.Finding, failOn, minGrade string, score *report.ScanScore) int {
	if failOn != "" {
		threshold := report.Severity(failOn)
		for _, f := range findings {
			if f.Status != "FAILED" {
				continue
			}
			if report.MeetsThreshold(f.Severity, threshold) {
				return 1
			}
		}
	}
	if minGrade != "" && score != nil {
		if !report.MeetsGradeThreshold(score.Grade, report.Grade(minGrade)) {
			return 1
		}
	}
	return 0
}

// runScan finalise le résultat et l'écrit.
func runScan(ctx context.Context, findings []report.Finding, mode, input string, ruleCount int) error {
	cfg, _ := loadConfig()
	minSev := report.Severity(cfg.Scan.MinSeverity)

	// Charge le fichier de suppressions .osc-policy-ignore (optionnel).
	ignoreFile, _ := ignores.Load(ignores.DefaultPath)

	filtered := make([]report.Finding, 0, len(findings))
	suppressedCount := 0
	for _, f := range findings {
		if f.Status == "FAILED" && !report.MeetsThreshold(f.Severity, minSev) {
			continue
		}
		// Filtrage des suppressions explicites (rule, resource).
		if ignoreFile != nil {
			if _, matched := ignoreFile.Match(string(f.RuleID), f.ResourceID); matched {
				suppressedCount++
				continue
			}
		}
		filtered = append(filtered, f)
	}
	if suppressedCount > 0 && !gflags.Quiet {
		fmt.Fprintf(os.Stderr, "ℹ %d finding(s) supprimé(s) via .osc-policy-ignore\n", suppressedCount)
	}
	report.SortFindings(filtered)

	score := report.ComputeScore(filtered)
	result := report.ScanResult{
		Summary:     report.BuildSummary(filtered),
		Score:       &score,
		Findings:    filtered,
		ScanDate:    time.Now(),
		ScanMode:    mode,
		PlanFile:    input,
		ToolVersion: version.Version,
	}

	if err := writeReport(os.Stdout, result, cfg.Scan.Output, cfg.Scan.Profile, input, gflags.NoColor, gflags.Quiet, ruleCount); err != nil {
		return err
	}

	code := computeExitCode(filtered, cfg.Scan.FailOn, cfg.Scan.MinGrade, &score)
	if code != 0 {
		os.Exit(code)
	}
	_ = ctx
	return nil
}
