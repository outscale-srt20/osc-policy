package docgen

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteIndex écrit l'index des règles regroupées par catégorie.
func WriteIndex(w io.Writer, rules []*RuleMetadata) error {
	byCat := map[string][]*RuleMetadata{}
	for _, r := range rules {
		byCat[r.Category] = append(byCat[r.Category], r)
	}

	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	for _, list := range byCat {
		sort.SliceStable(list, func(i, j int) bool {
			oi, oj := order[strings.ToUpper(list[i].Severity)], order[strings.ToUpper(list[j].Severity)]
			if oi != oj {
				return oi < oj
			}
			return list[i].ID < list[j].ID
		})
	}

	fmt.Fprintf(w, "# Référence des règles osc-policy\n\n")

	cats := []string{"security", "finops", "compliance"}
	for _, cat := range cats {
		list := byCat[cat]
		if len(list) == 0 {
			continue
		}
		title := strings.Title(cat)
		fmt.Fprintf(w, "## %s (%d règles)\n\n", title, len(list))
		fmt.Fprintf(w, "| ID | Sévérité | Ressource | Titre |\n|:---|:---|:---|:---|\n")
		for _, r := range list {
			res := strings.Join(r.ResourceTypes, ", ")
			fmt.Fprintf(w, "| [%s](%s/%s.md) | %s | %s | %s |\n",
				r.ID, cat, r.ID, sevEmoji(r.Severity), res, r.Title)
		}
		fmt.Fprintln(w)
	}
	return nil
}
