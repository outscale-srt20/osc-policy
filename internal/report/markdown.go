package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteMarkdown écrit un rapport Markdown.
func WriteMarkdown(w io.Writer, r ScanResult) error {
	fmt.Fprintf(w, "# Rapport osc-policy\n\n")
	fmt.Fprintf(w, "- **Date** : %s\n", r.ScanDate.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "- **Mode** : %s\n", r.ScanMode)
	if r.Region != "" {
		fmt.Fprintf(w, "- **Région** : %s\n", r.Region)
	}
	if r.PlanFile != "" {
		fmt.Fprintf(w, "- **Plan** : %s\n", r.PlanFile)
	}
	fmt.Fprintf(w, "- **Version** : %s\n\n", r.ToolVersion)

	s := r.Summary
	if r.Score != nil {
		sc := *r.Score
		fmt.Fprintf(w, "## Score\n\n")
		fmt.Fprintf(w, "- **Note globale** : **%s** (%d/100) — %s\n", sc.Grade, sc.Score, sc.Label)
		if sc.CriticalCapApplied {
			fmt.Fprintf(w, "- ⚠ **Plafond CRITICAL appliqué** : le score est borné à 45 tant qu'au moins un finding CRITICAL subsiste.\n")
		}
		if len(sc.Services) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "| Service | Score | Grade | Fail | CRIT | HIGH | MED | LOW |")
			fmt.Fprintln(w, "|---|---:|:---:|---:|---:|---:|---:|---:|")
			for _, svc := range sc.Services {
				fmt.Fprintf(w, "| %s | %d/100 | %s | %d | %d | %d | %d | %d |\n",
					svc.Service, svc.Score, svc.Grade, svc.TotalFail,
					svc.Counts[SeverityCritical], svc.Counts[SeverityHigh],
					svc.Counts[SeverityMedium], svc.Counts[SeverityLow])
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Résumé\n\n")
	fmt.Fprintf(w, "| Métrique | Valeur |\n|---|---|\n")
	fmt.Fprintf(w, "| Findings | %d |\n", s.Failed)
	fmt.Fprintf(w, "| 🔴 CRITICAL | %d |\n", s.BySeverity[SeverityCritical])
	fmt.Fprintf(w, "| 🟠 HIGH | %d |\n", s.BySeverity[SeverityHigh])
	fmt.Fprintf(w, "| 🟡 MEDIUM | %d |\n", s.BySeverity[SeverityMedium])
	fmt.Fprintf(w, "| 🔵 LOW | %d |\n", s.BySeverity[SeverityLow])

	if s.TotalMonthlyCost > 0 || s.TotalPotentialSavings > 0 {
		fmt.Fprintf(w, "| Coût mensuel estimé | %.2f € |\n", s.TotalMonthlyCost)
		fmt.Fprintf(w, "| Économies potentielles | %.2f € |\n", s.TotalPotentialSavings)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## Findings (%d)\n\n", s.Failed)

	for _, f := range r.Findings {
		if f.Status != "FAILED" {
			continue
		}
		fmt.Fprintf(w, "### %s %s — %s\n\n", sevIcon(f.Severity), f.RuleID, f.RuleTitle)
		fmt.Fprintf(w, "- **Sévérité** : %s\n", f.Severity)
		fmt.Fprintf(w, "- **Catégorie** : %s\n", f.Category)
		fmt.Fprintf(w, "- **Ressource** : `%s`\n", f.ResourceType)
		if f.ResourceAddress != "" {
			fmt.Fprintf(w, "- **Address** : `%s`\n", f.ResourceAddress)
		}
		if f.ResourceID != "" {
			fmt.Fprintf(w, "- **ID** : `%s`\n", f.ResourceID)
		}
		fmt.Fprintf(w, "\n%s\n\n", f.Message)

		if f.Remediation != "" {
			fmt.Fprintf(w, "**Remédiation** :\n\n%s\n\n", strings.TrimSpace(f.Remediation))
		}
		if len(f.References) > 0 {
			fmt.Fprintln(w, "**Références** :")
			for _, ref := range f.References {
				fmt.Fprintf(w, "- %s\n", ref)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	}
	return nil
}
