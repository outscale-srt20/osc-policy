package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
)

func docsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "docs",
		Short: "Générer la documentation des règles",
	}
	c.AddCommand(docsGenerateCmd())
	return c
}

func docsGenerateCmd() *cobra.Command {
	var (
		outputDir string
		format    string
		lang      string
	)

	c := &cobra.Command{
		Use:   "generate",
		Short: "Générer docs/rules à partir des métadonnées Rego",
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
				rules = append(rules, meta)
			}

			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return err
			}

			// Index
			indexPath := filepath.Join(outputDir, "README.md")
			idx, err := os.Create(indexPath)
			if err != nil {
				return err
			}
			if err := docgen.WriteIndex(idx, rules); err != nil {
				idx.Close()
				return err
			}
			idx.Close()

			// Un fichier par règle
			for _, r := range rules {
				catDir := filepath.Join(outputDir, r.Category)
				if err := os.MkdirAll(catDir, 0755); err != nil {
					return err
				}
				f, err := os.Create(filepath.Join(catDir, r.ID+".md"))
				if err != nil {
					return err
				}
				if err := docgen.WriteRuleMarkdown(f, r); err != nil {
					f.Close()
					return err
				}
				f.Close()
			}

			fmt.Printf("✅ %d règles documentées dans %s\n", len(rules), outputDir)
			_ = format
			_ = lang
			return nil
		},
	}
	c.Flags().StringVar(&outputDir, "output-dir", "./docs/rules", "Répertoire de sortie")
	c.Flags().StringVar(&format, "format", "markdown", "markdown|html|astro")
	c.Flags().StringVar(&lang, "lang", "fr", "Langue: fr|en")
	return c
}
