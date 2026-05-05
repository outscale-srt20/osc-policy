package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
	"github.com/outscale-srt20/osc-policy/internal/report"
)

func reportCmd() *cobra.Command {
	var (
		framework string
		scanFile  string
		output    string
		outFile   string
	)

	c := &cobra.Command{
		Use:   "report",
		Short: "Générer un rapport de conformité ciblé sur un framework (SecNumCloud, ANSSI, CIS, ISO)",
		Long: `Produit un rapport de conformité au format markdown listant, pour chaque
contrôle d'un framework de référence (SECNUMCLOUD-3.2, ANSSI-BP-028,
CIS-CONTROLS-V8, ISO-27001-2022, ISO-27017) :

  - les règles osc-policy qui le couvrent,
  - le statut (PASSED / FAILED / NOT_ASSESSED) si un fichier scan JSON est fourni,
  - les ressources non-conformes.

Cas d'usage :
  - Audit RSSI : rapport "où en est-on sur SecNumCloud 3.2 ?"
  - Conformité documentée : trace pour ISO 27001 / commissaire aux comptes
  - Suivi trimestriel d'une certification

Exemples :
  osc-policy report --framework secnumcloud_3_2
  osc-policy report --framework anssi_bp_028 --scan scan.json --output-file audit.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if framework == "" {
				return fmt.Errorf("--framework requis (ex: secnumcloud_3_2, anssi_bp_028, cis_controls_v8, iso_27001_2022, iso_27017)")
			}
			fw := normalizeFrameworkID(framework)

			rules, err := loadAllRules()
			if err != nil {
				return err
			}

			// Filter rules that map to this framework
			byControl := map[string][]*docgen.RuleMetadata{}
			for _, r := range rules {
				controls, ok := r.Compliance[fw]
				if !ok {
					continue
				}
				for _, c := range controls {
					byControl[c] = append(byControl[c], r)
				}
			}

			if len(byControl) == 0 {
				return fmt.Errorf("aucune règle ne couvre le framework '%s' — vérifier l'ID ou enrichir le mapping compliance des règles", fw)
			}

			// Optionally load a scan to compute pass/fail per control
			var findingsByRule map[string][]report.Finding
			if scanFile != "" {
				sc, err := loadResult(scanFile)
				if err != nil {
					return err
				}
				findingsByRule = groupFindingsByRule(sc.Findings)
			}

			out := generateComplianceReport(fw, byControl, findingsByRule)

			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(out), 0644); err != nil {
					return err
				}
				fmt.Printf("✓ Rapport écrit dans %s\n", outFile)
				return nil
			}
			_ = output
			fmt.Print(out)
			return nil
		},
	}
	c.Flags().StringVar(&framework, "framework", "", "ID du framework (secnumcloud_3_2, anssi_bp_028, cis_controls_v8, iso_27001_2022, iso_27017)")
	c.Flags().StringVar(&scanFile, "scan", "", "Fichier scan JSON pour calculer le statut par contrôle (optionnel)")
	c.Flags().StringVar(&output, "output", "markdown", "Format : markdown (seul format supporté actuellement)")
	c.Flags().StringVar(&outFile, "output-file", "", "Fichier de sortie (défaut : stdout)")
	return c
}

func normalizeFrameworkID(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

func loadAllRules() ([]*docgen.RuleMetadata, error) {
	embedded, err := engine.LoadEmbedded()
	if err != nil {
		return nil, err
	}
	var rules []*docgen.RuleMetadata
	for path, src := range embedded.Modules {
		if strings.HasSuffix(path, "_test.rego") {
			continue
		}
		meta, err := docgen.ParseRegoMetadata(path, src)
		if err != nil {
			continue
		}
		rules = append(rules, meta)
	}
	return rules, nil
}

func groupFindingsByRule(fs []report.Finding) map[string][]report.Finding {
	out := map[string][]report.Finding{}
	for _, f := range fs {
		if f.Status != "FAILED" {
			continue
		}
		out[f.RuleID] = append(out[f.RuleID], f)
	}
	return out
}

func generateComplianceReport(framework string, byControl map[string][]*docgen.RuleMetadata, findingsByRule map[string][]report.Finding) string {
	var sb strings.Builder

	_, _ = fmt.Fprintf(&sb, "# Rapport de conformité — %s\n\n", strings.ToUpper(framework))
	_, _ = fmt.Fprintf(&sb, "_Généré le %s par osc-policy_\n\n", time.Now().Format("2006-01-02 15:04"))
	if findingsByRule == nil {
		sb.WriteString("> Aucun scan fourni. Le rapport liste uniquement la couverture théorique du framework par les règles disponibles.\n\n")
	}

	// Sort controls deterministically
	controls := make([]string, 0, len(byControl))
	for c := range byControl {
		controls = append(controls, c)
	}
	sort.Strings(controls)

	// Aggregated stats
	totalControls := len(controls)
	passed, failed, notAssessed := 0, 0, 0

	rows := []string{}
	for _, ctrl := range controls {
		rules := byControl[ctrl]
		ruleIDs := []string{}
		controlStatus := "PASSED"
		nbFindings := 0

		for _, r := range rules {
			ruleIDs = append(ruleIDs, r.ID)
			if findingsByRule != nil {
				if fs, ok := findingsByRule[r.ID]; ok {
					controlStatus = "FAILED"
					nbFindings += len(fs)
				}
			}
		}
		if findingsByRule == nil {
			controlStatus = "ASSESSED"
		}

		switch controlStatus {
		case "PASSED":
			passed++
		case "FAILED":
			failed++
		default:
			notAssessed++
		}

		statusIcon := "ℹ️"
		switch controlStatus {
		case "PASSED":
			statusIcon = "✅"
		case "FAILED":
			statusIcon = "❌"
		}

		rows = append(rows, fmt.Sprintf("| %s `%s` | %s | %s | %d |",
			statusIcon, ctrl, strings.Join(ruleIDs, ", "), controlStatus, nbFindings,
		))
	}

	if findingsByRule != nil {
		sb.WriteString("## Synthèse\n\n")
		_, _ = fmt.Fprintf(&sb, "- Contrôles couverts par osc-policy : **%d**\n", totalControls)
		_, _ = fmt.Fprintf(&sb, "- ✅ Conformes (aucun finding) : **%d**\n", passed)
		_, _ = fmt.Fprintf(&sb, "- ❌ Non-conformes (findings actifs) : **%d**\n", failed)
		if totalControls > 0 {
			pct := 100 * passed / totalControls
			_, _ = fmt.Fprintf(&sb, "- Score de conformité : **%d %%**\n\n", pct)
		}
	} else {
		_, _ = fmt.Fprintf(&sb, "Contrôles du framework couverts par les règles osc-policy : **%d**\n\n", totalControls)
	}

	sb.WriteString("## Détail par contrôle\n\n")
	sb.WriteString("| Statut | Contrôle | Règles couvrantes | Évaluation | Findings |\n")
	sb.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, row := range rows {
		sb.WriteString(row + "\n")
	}
	sb.WriteString("\n")

	// If we have findings, list them grouped by control
	if findingsByRule != nil {
		hasFailed := false
		for _, fs := range findingsByRule {
			if len(fs) > 0 {
				hasFailed = true
				break
			}
		}
		if hasFailed {
			sb.WriteString("## Findings actifs\n\n")
			sortedRuleIDs := []string{}
			for rid := range findingsByRule {
				sortedRuleIDs = append(sortedRuleIDs, rid)
			}
			sort.Strings(sortedRuleIDs)
			for _, rid := range sortedRuleIDs {
				fs := findingsByRule[rid]
				if len(fs) == 0 {
					continue
				}
				_, _ = fmt.Fprintf(&sb, "### %s — %s\n\n", rid, fs[0].RuleTitle)
				for _, f := range fs {
					_, _ = fmt.Fprintf(&sb, "- **%s** `%s` — %s\n", f.Severity, f.ResourceID, f.Message)
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("---\n\n")
	sb.WriteString("_Pour la documentation détaillée d'une règle : `osc-policy explain <rule-id>`._\n")
	sb.WriteString("_Pour une suggestion de remédiation : `osc-policy fix --rule <rule-id> --resource <id>`._\n")

	_ = json.Marshal // keep import (used elsewhere in cmd package)
	return sb.String()
}
