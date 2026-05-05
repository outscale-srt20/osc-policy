package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
)

func explainCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "explain <rule-id>",
		Short: "Afficher la documentation détaillée d'une règle",
		Long: `Affiche la documentation complète d'une règle : description, sévérité,
exemples non-conforme et conforme, étapes de remédiation, frameworks de
conformité couverts et références.

Exemple :
  osc-policy explain OSC-SG-001
  osc-policy explain osc-oks-001`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := strings.ToUpper(args[0])
			meta, err := findRuleByID(ruleID)
			if err != nil {
				return err
			}
			renderExplain(os.Stdout, meta)
			return nil
		},
	}
	return c
}

func findRuleByID(ruleID string) (*docgen.RuleMetadata, error) {
	embedded, err := engine.LoadEmbedded()
	if err != nil {
		return nil, err
	}
	var matches []*docgen.RuleMetadata
	for path, src := range embedded.Modules {
		if strings.HasSuffix(path, "_test.rego") {
			continue
		}
		meta, err := docgen.ParseRegoMetadata(path, src)
		if err != nil {
			continue
		}
		if strings.EqualFold(meta.ID, ruleID) {
			return meta, nil
		}
		// Approximate match for typos: same prefix
		if strings.HasPrefix(strings.ToUpper(meta.ID), ruleID) {
			matches = append(matches, meta)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		ids := []string{}
		for _, m := range matches {
			ids = append(ids, m.ID)
		}
		return nil, fmt.Errorf("règle '%s' ambiguë, candidats : %s", ruleID, strings.Join(ids, ", "))
	}
	return nil, fmt.Errorf("règle '%s' introuvable (utiliser `osc-policy rules list` pour voir les IDs disponibles)", ruleID)
}

// renderExplain produit un affichage friendly d'une règle.
func renderExplain(w *os.File, m *docgen.RuleMetadata) {
	rule := lipgloss.NewStyle().Bold(true)
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	sev := severityStyle(m.Severity)

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, header.Render(strings.Repeat("─", 78)))
	_, _ = fmt.Fprintf(w, "  %s  %s\n", sev.Render(strings.ToUpper(m.Severity)), rule.Render(m.ID))
	_, _ = fmt.Fprintf(w, "  %s\n", m.Title)
	_, _ = fmt.Fprintln(w, header.Render(strings.Repeat("─", 78)))
	_, _ = fmt.Fprintln(w)

	if m.Description != "" {
		_, _ = fmt.Fprintln(w, header.Render("Description"))
		_, _ = fmt.Fprintln(w, indent(strings.TrimSpace(m.Description), "  "))
		_, _ = fmt.Fprintln(w)
	}

	if m.Category != "" || m.Profile != "" || len(m.ResourceTypes) > 0 || m.Source != "" {
		_, _ = fmt.Fprintln(w, header.Render("Métadonnées"))
		if m.Category != "" {
			_, _ = fmt.Fprintf(w, "  • Catégorie       : %s\n", m.Category)
		}
		if m.Profile != "" {
			_, _ = fmt.Fprintf(w, "  • Profile         : %s\n", m.Profile)
		}
		if m.Source != "" {
			_, _ = fmt.Fprintf(w, "  • Source          : %s\n", m.Source)
		}
		if len(m.ResourceTypes) > 0 {
			_, _ = fmt.Fprintf(w, "  • Resource types  : %s\n", strings.Join(m.ResourceTypes, ", "))
		}
		_, _ = fmt.Fprintln(w)
	}

	if m.NoncompliantExample != "" {
		_, _ = fmt.Fprintln(w, header.Render("❌ Exemple non-conforme"))
		_, _ = fmt.Fprintln(w, indent(strings.TrimSpace(m.NoncompliantExample), "  "))
		_, _ = fmt.Fprintln(w)
	}

	if m.CompliantExample != "" {
		_, _ = fmt.Fprintln(w, header.Render("✅ Exemple conforme"))
		_, _ = fmt.Fprintln(w, indent(strings.TrimSpace(m.CompliantExample), "  "))
		_, _ = fmt.Fprintln(w)
	}

	if m.Remediation != "" {
		_, _ = fmt.Fprintln(w, header.Render("🔧 Remédiation"))
		_, _ = fmt.Fprintln(w, indent(strings.TrimSpace(m.Remediation), "  "))
		_, _ = fmt.Fprintln(w)
	}

	if len(m.Compliance) > 0 {
		_, _ = fmt.Fprintln(w, header.Render("📋 Conformité"))
		for fw, controls := range m.Compliance {
			_, _ = fmt.Fprintf(w, "  • %-20s : %s\n", strings.ToUpper(fw), strings.Join(controls, ", "))
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(m.References) > 0 {
		_, _ = fmt.Fprintln(w, header.Render("Références"))
		for _, ref := range m.References {
			_, _ = fmt.Fprintf(w, "  • %s\n", ref)
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w, dim.Render(fmt.Sprintf("  Source: %s", m.RegoFile)))
	_, _ = fmt.Fprintln(w)
}

func severityStyle(sev string) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return base.Foreground(lipgloss.Color("15")).Background(lipgloss.Color("9"))
	case "HIGH":
		return base.Foreground(lipgloss.Color("15")).Background(lipgloss.Color("208"))
	case "MEDIUM":
		return base.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("11"))
	case "LOW":
		return base.Foreground(lipgloss.Color("15")).Background(lipgloss.Color("12"))
	default:
		return base.Foreground(lipgloss.Color("8"))
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
