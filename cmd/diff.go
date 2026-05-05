package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/report"
)

func diffCmd() *cobra.Command {
	var (
		failOnNew bool
		format    string
	)

	c := &cobra.Command{
		Use:   "diff <previous.json> <current.json>",
		Short: "Comparer deux scans JSON et afficher les findings nouveaux/résolus",
		Long: `Compare deux rapports osc-policy au format JSON et identifie :
  - les findings NOUVEAUX dans le scan courant (régressions)
  - les findings RÉSOLUS depuis le scan précédent (progrès)
  - les findings INCHANGÉS (état stable)

Cas d'usage typiques :
  - CI : comparer le scan de la MR avec le scan de main pour détecter les
    régressions avant merge.
  - Suivi hebdomadaire : voir l'évolution de la posture entre 2 scans live.

Exemple :
  osc-policy diff scan-main.json scan-mr.json --fail-on-new`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			prev, err := loadResult(args[0])
			if err != nil {
				return fmt.Errorf("lecture %s: %w", args[0], err)
			}
			curr, err := loadResult(args[1])
			if err != nil {
				return fmt.Errorf("lecture %s: %w", args[1], err)
			}

			d := computeDiff(prev.Findings, curr.Findings)

			switch format {
			case "json":
				renderDiffJSON(d)
			default:
				renderDiffTerminal(d, args[0], args[1])
			}

			if failOnNew && len(d.New) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&failOnNew, "fail-on-new", false, "Exit code non-zéro si au moins 1 nouveau finding")
	c.Flags().StringVar(&format, "format", "terminal", "Format de sortie : terminal | json")
	return c
}

// findingDiff represents the diff result between two scans.
type findingDiff struct {
	New       []report.Finding `json:"new"`
	Resolved  []report.Finding `json:"resolved"`
	Unchanged []report.Finding `json:"unchanged"`
}

// loadResult reads a scan JSON file (output of `osc-policy scan ... --output json`).
func loadResult(path string) (*report.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r report.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return &r, nil
}

// findingKey identifies a finding uniquely by (rule, resource).
// We don't include the timestamp or message (which may evolve).
func findingKey(f report.Finding) string {
	return f.RuleID + "|" + f.ResourceID
}

func computeDiff(prev, curr []report.Finding) findingDiff {
	prevMap := map[string]report.Finding{}
	for _, f := range prev {
		if f.Status != "FAILED" {
			continue
		}
		prevMap[findingKey(f)] = f
	}
	currMap := map[string]report.Finding{}
	for _, f := range curr {
		if f.Status != "FAILED" {
			continue
		}
		currMap[findingKey(f)] = f
	}

	var d findingDiff
	for k, f := range currMap {
		if _, existed := prevMap[k]; !existed {
			d.New = append(d.New, f)
		} else {
			d.Unchanged = append(d.Unchanged, f)
		}
	}
	for k, f := range prevMap {
		if _, stillThere := currMap[k]; !stillThere {
			d.Resolved = append(d.Resolved, f)
		}
	}

	sortBySeverity(d.New)
	sortBySeverity(d.Resolved)
	sortBySeverity(d.Unchanged)
	return d
}

func sortBySeverity(fs []report.Finding) {
	rank := map[report.Severity]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := rank[fs[i].Severity], rank[fs[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

func renderDiffTerminal(d findingDiff, prevPath, currPath string) {
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	good := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	bad := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	sep := strings.Repeat("─", 78)

	fmt.Println()
	fmt.Println(sep)
	fmt.Printf("  %s\n", header.Render("Diff de scans osc-policy"))
	fmt.Printf("  %s %s\n", dim.Render("avant :"), prevPath)
	fmt.Printf("  %s %s\n", dim.Render("après :"), currPath)
	fmt.Println(sep)
	fmt.Println()

	fmt.Printf("  %s %s    %s %s    %s %s\n",
		bad.Render("🆕 nouveaux:"), bad.Render(fmt.Sprintf("%d", len(d.New))),
		good.Render("✓ résolus:"), good.Render(fmt.Sprintf("%d", len(d.Resolved))),
		dim.Render("= inchangés:"), dim.Render(fmt.Sprintf("%d", len(d.Unchanged))),
	)
	fmt.Println()

	if len(d.New) > 0 {
		fmt.Println(bad.Render("🆕 Nouveaux findings (régressions)"))
		printFindings(d.New)
		fmt.Println()
	}

	if len(d.Resolved) > 0 {
		fmt.Println(good.Render("✓ Findings résolus depuis le scan précédent"))
		printFindings(d.Resolved)
		fmt.Println()
	}

	if len(d.New) == 0 && len(d.Resolved) == 0 {
		fmt.Println("  " + dim.Render("Aucun changement de posture entre les 2 scans."))
		fmt.Println()
	}
}

func printFindings(fs []report.Finding) {
	for _, f := range fs {
		fmt.Printf("  • [%s] %s — %s — %s\n",
			f.Severity, f.RuleID,
			truncateStr(f.ResourceAddress, 30),
			truncateStr(f.Message, 80),
		)
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func renderDiffJSON(d findingDiff) {
	out, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(out))
}
