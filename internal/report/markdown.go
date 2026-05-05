package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteMarkdown écrit un rapport Markdown.
func WriteMarkdown(w io.Writer, r ScanResult) error {
	_, _ = fmt.Fprintf(w, "# Rapport osc-policy\n\n")
	_, _ = fmt.Fprintf(w, "- **Date** : %s\n", r.ScanDate.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(w, "- **Mode** : %s\n", r.ScanMode)
	if r.Region != "" {
		_, _ = fmt.Fprintf(w, "- **Région** : %s\n", r.Region)
	}
	if r.PlanFile != "" {
		_, _ = fmt.Fprintf(w, "- **Plan** : %s\n", r.PlanFile)
	}
	_, _ = fmt.Fprintf(w, "- **Version** : %s\n\n", r.ToolVersion)

	s := r.Summary
	if r.Score != nil {
		sc := *r.Score
		_, _ = fmt.Fprintf(w, "## Score\n\n")
		_, _ = fmt.Fprintf(w, "- **Note globale** : **%s** (%d/100) — %s\n", sc.Grade, sc.Score, sc.Label)
		if sc.CriticalCapApplied {
			_, _ = fmt.Fprintf(w, "- ⚠ **Plafond CRITICAL appliqué** : le score est borné à 45 tant qu'au moins un finding CRITICAL subsiste.\n")
		}
		if len(sc.Services) > 0 {
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "| Service | Score | Grade | Fail | CRIT | HIGH | MED | LOW |")
			_, _ = fmt.Fprintln(w, "|---|---:|:---:|---:|---:|---:|---:|---:|")
			for _, svc := range sc.Services {
				_, _ = fmt.Fprintf(w, "| %s | %d/100 | %s | %d | %d | %d | %d | %d |\n",
					svc.Service, svc.Score, svc.Grade, svc.TotalFail,
					svc.Counts[SeverityCritical], svc.Counts[SeverityHigh],
					svc.Counts[SeverityMedium], svc.Counts[SeverityLow])
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "## Résumé\n\n")
	_, _ = fmt.Fprintf(w, "| Métrique | Valeur |\n|---|---|\n")
	_, _ = fmt.Fprintf(w, "| Findings | %d |\n", s.Failed)
	_, _ = fmt.Fprintf(w, "| 🔴 CRITICAL | %d |\n", s.BySeverity[SeverityCritical])
	_, _ = fmt.Fprintf(w, "| 🟠 HIGH | %d |\n", s.BySeverity[SeverityHigh])
	_, _ = fmt.Fprintf(w, "| 🟡 MEDIUM | %d |\n", s.BySeverity[SeverityMedium])
	_, _ = fmt.Fprintf(w, "| 🔵 LOW | %d |\n", s.BySeverity[SeverityLow])

	if s.TotalMonthlyCost > 0 || s.TotalPotentialSavings > 0 {
		_, _ = fmt.Fprintf(w, "| Coût mensuel estimé | %.2f € |\n", s.TotalMonthlyCost)
		_, _ = fmt.Fprintf(w, "| Économies potentielles | %.2f € |\n", s.TotalPotentialSavings)
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "## Findings (%d)\n\n", s.Failed)

	for _, f := range r.Findings {
		if f.Status != "FAILED" {
			continue
		}
		_, _ = fmt.Fprintf(w, "### %s %s — %s\n\n", sevIcon(f.Severity), f.RuleID, f.RuleTitle)
		_, _ = fmt.Fprintf(w, "- **Sévérité** : %s\n", f.Severity)
		_, _ = fmt.Fprintf(w, "- **Catégorie** : %s\n", f.Category)
		_, _ = fmt.Fprintf(w, "- **Ressource** : `%s`\n", f.ResourceType)
		if f.ResourceAddress != "" {
			_, _ = fmt.Fprintf(w, "- **Address** : `%s`\n", f.ResourceAddress)
		}
		if f.ResourceID != "" {
			_, _ = fmt.Fprintf(w, "- **ID** : `%s`\n", f.ResourceID)
		}
		_, _ = fmt.Fprintf(w, "\n%s\n\n", f.Message)

		if f.Remediation != "" {
			_, _ = fmt.Fprintf(w, "**Remédiation** :\n\n%s\n\n", strings.TrimSpace(f.Remediation))
		}
		if len(f.References) > 0 {
			_, _ = fmt.Fprintln(w, "**Références** :")
			for _, ref := range f.References {
				_, _ = fmt.Fprintf(w, "- %s\n", ref)
			}
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintln(w, "---")
		_, _ = fmt.Fprintln(w)
	}
	return nil
}
