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
	fmt.Fprintf(w, "---\n")
	fmt.Fprintf(w, "id: %s\n", r.ID)
	fmt.Fprintf(w, "title: %s\n", r.Title)
	fmt.Fprintf(w, "severity: %s\n", r.Severity)
	fmt.Fprintf(w, "category: %s\n", r.Category)
	if len(r.ResourceTypes) > 0 {
		fmt.Fprintf(w, "resource_types: [%s]\n", strings.Join(r.ResourceTypes, ", "))
	}
	if r.Source != "" {
		fmt.Fprintf(w, "source: %s\n", r.Source)
	}
	fmt.Fprintf(w, "---\n\n")

	fmt.Fprintf(w, "# %s — %s\n\n", r.ID, r.Title)

	fmt.Fprintf(w, "| Champ | Valeur |\n|---|---|\n")
	fmt.Fprintf(w, "| ID | %s |\n", r.ID)
	fmt.Fprintf(w, "| Sévérité | %s |\n", sevEmoji(r.Severity))
	fmt.Fprintf(w, "| Catégorie | %s |\n", r.Category)
	if len(r.ResourceTypes) > 0 {
		fmt.Fprintf(w, "| Ressources | %s |\n", strings.Join(r.ResourceTypes, ", "))
	}
	if r.Source != "" {
		fmt.Fprintf(w, "| Mode | %s |\n", r.Source)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## Description du problème\n\n%s\n\n", strings.TrimSpace(r.Description))

	if r.NoncompliantExample != "" {
		fmt.Fprintf(w, "## Configuration NON CONFORME ❌\n\n```hcl\n%s\n```\n\n",
			strings.TrimRight(r.NoncompliantExample, "\n"))
	}
	if r.CompliantExample != "" {
		fmt.Fprintf(w, "## Configuration CONFORME ✅\n\n```hcl\n%s\n```\n\n",
			strings.TrimRight(r.CompliantExample, "\n"))
	}

	if r.Remediation != "" {
		fmt.Fprintf(w, "## Étapes de remédiation\n\n%s\n\n", strings.TrimSpace(r.Remediation))
	}

	if len(r.References) > 0 {
		fmt.Fprintf(w, "## Références\n\n")
		for _, ref := range r.References {
			fmt.Fprintf(w, "- %s\n", ref)
		}
		fmt.Fprintln(w)
	}

	if r.RegoContent != "" {
		fmt.Fprintf(w, "## Code Rego\n\n```rego\n%s\n```\n\n",
			strings.TrimRight(r.RegoContent, "\n"))
	}

	fmt.Fprintf(w, "---\n")
	fmt.Fprintf(w, "*Généré automatiquement par `osc-policy docs generate`*\n")
	return nil
}
