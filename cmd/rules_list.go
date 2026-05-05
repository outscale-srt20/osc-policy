package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
)

func rulesListCmd() *cobra.Command {
	var (
		profile  string
		severity string
		format   string
	)

	c := &cobra.Command{
		Use:   "list",
		Short: "Lister toutes les règles disponibles",
		RunE: func(cmd *cobra.Command, args []string) error {
			embedded, err := engine.LoadEmbedded()
			if err != nil {
				return err
			}
			rules := []*docgen.RuleMetadata{}
			for path, src := range embedded.Modules {
				if strings.HasSuffix(path, "_test.rego") {
					continue
				}
				meta, err := docgen.ParseRegoMetadata(path, src)
				if err != nil {
					continue
				}
				if profile != "" && profile != "all" && meta.Profile != profile {
					continue
				}
				if severity != "" && !strings.EqualFold(meta.Severity, severity) {
					continue
				}
				rules = append(rules, meta)
			}

			sort.SliceStable(rules, func(i, j int) bool {
				sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
				oi := sevOrder[strings.ToUpper(rules[i].Severity)]
				oj := sevOrder[strings.ToUpper(rules[j].Severity)]
				if oi != oj {
					return oi < oj
				}
				return rules[i].ID < rules[j].ID
			})

			switch format {
			case "json":
				return json.NewEncoder(os.Stdout).Encode(rules)
			case "markdown":
				return docgen.WriteIndex(os.Stdout, rules)
			default:
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"ID", "SEVERITY", "CATEGORY", "TITLE"})
				table.SetBorder(false)
				table.SetAutoWrapText(false)
				for _, r := range rules {
					table.Append([]string{r.ID, r.Severity, r.Category, r.Title})
				}
				table.Render()
				fmt.Printf("\nTotal: %d règles\n", len(rules))
			}
			return nil
		},
	}

	c.Flags().StringVar(&profile, "profile", "", "Filtrer par profil")
	c.Flags().StringVar(&severity, "severity", "", "Filtrer par sévérité")
	c.Flags().StringVar(&format, "output", "terminal", "terminal|json|markdown")
	return c
}
