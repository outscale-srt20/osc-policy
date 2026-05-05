package docgen

import (
	"fmt"
	"io"
	"strings"
)

func sevEmoji(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "🔴 CRITICAL"
	case "HIGH":
		return "🟠 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	case "LOW":
		return "🔵 LOW"
	case "INFO":
		return "⚪ INFO"
	}
	return s
}

// WriteRuleMarkdown écrit la documentation d'une règle.
func WriteRuleMarkdown(w io.Writer, r *RuleMetadata) error {
	_, _ = fmt.Fprintf(w, "---\n")
	_, _ = fmt.Fprintf(w, "id: %s\n", r.ID)
	_, _ = fmt.Fprintf(w, "title: %s\n", r.Title)
	_, _ = fmt.Fprintf(w, "severity: %s\n", r.Severity)
	_, _ = fmt.Fprintf(w, "category: %s\n", r.Category)
	if len(r.ResourceTypes) > 0 {
		_, _ = fmt.Fprintf(w, "resource_types: [%s]\n", strings.Join(r.ResourceTypes, ", "))
	}
	if r.Source != "" {
		_, _ = fmt.Fprintf(w, "source: %s\n", r.Source)
	}
	_, _ = fmt.Fprintf(w, "---\n\n")

	_, _ = fmt.Fprintf(w, "# %s — %s\n\n", r.ID, r.Title)

	_, _ = fmt.Fprintf(w, "| Champ | Valeur |\n|---|---|\n")
	_, _ = fmt.Fprintf(w, "| ID | %s |\n", r.ID)
	_, _ = fmt.Fprintf(w, "| Sévérité | %s |\n", sevEmoji(r.Severity))
	_, _ = fmt.Fprintf(w, "| Catégorie | %s |\n", r.Category)
	if len(r.ResourceTypes) > 0 {
		_, _ = fmt.Fprintf(w, "| Ressources | %s |\n", strings.Join(r.ResourceTypes, ", "))
	}
	if r.Source != "" {
		_, _ = fmt.Fprintf(w, "| Mode | %s |\n", r.Source)
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "## Description du problème\n\n%s\n\n", strings.TrimSpace(r.Description))

	if r.NoncompliantExample != "" {
		_, _ = fmt.Fprintf(w, "## Configuration NON CONFORME ❌\n\n```hcl\n%s\n```\n\n",
			strings.TrimRight(r.NoncompliantExample, "\n"))
	}
	if r.CompliantExample != "" {
		_, _ = fmt.Fprintf(w, "## Configuration CONFORME ✅\n\n```hcl\n%s\n```\n\n",
			strings.TrimRight(r.CompliantExample, "\n"))
	}

	if r.Remediation != "" {
		_, _ = fmt.Fprintf(w, "## Étapes de remédiation\n\n%s\n\n", strings.TrimSpace(r.Remediation))
	}

	if len(r.References) > 0 {
		_, _ = fmt.Fprintf(w, "## Références\n\n")
		for _, ref := range r.References {
			_, _ = fmt.Fprintf(w, "- %s\n", ref)
		}
		_, _ = fmt.Fprintln(w)
	}

	if r.RegoContent != "" {
		_, _ = fmt.Fprintf(w, "## Code Rego\n\n```rego\n%s\n```\n\n",
			strings.TrimRight(r.RegoContent, "\n"))
	}

	_, _ = fmt.Fprintf(w, "---\n")
	_, _ = fmt.Fprintf(w, "*Généré automatiquement par `osc-policy docs generate`*\n")
	return nil
}
