package cmd

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/ignores"
)

func suppressCmd() *cobra.Command {
	var (
		ruleID   string
		resource string
		reason   string
		expires  string
		filePath string
		list     bool
	)

	c := &cobra.Command{
		Use:   "suppress",
		Short: "Ajouter une suppression de finding (versionné dans .osc-policy-ignore)",
		Long: `Ajoute une entrée au fichier .osc-policy-ignore qui supprime un finding
spécifique d'une combinaison (rule, resource). Chaque suppression doit avoir
une raison documentée et idéalement une date d'expiration.

Le fichier .osc-policy-ignore doit être versionné en Git pour audit. Les
suppressions expirent automatiquement à la date indiquée.

Exemples :
  osc-policy suppress --rule OSC-SG-001 --resource sg-12345 \
      --reason "Bastion temporaire validé par RSSI #ticket-42" \
      --expires 2026-12-31

  osc-policy suppress --list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				filePath = ignores.DefaultPath
			}
			f, err := ignores.Load(filePath)
			if err != nil {
				return err
			}

			if list {
				return listSuppressions(f, filePath)
			}

			if ruleID == "" || resource == "" || reason == "" {
				return fmt.Errorf("--rule, --resource et --reason sont requis")
			}
			ruleID = strings.ToUpper(ruleID)

			username := "unknown"
			if u, err := user.Current(); err == nil {
				username = u.Username
			}

			f.Add(ignores.Ignore{
				Rule:     ruleID,
				Resource: resource,
				Reason:   reason,
				Expires:  expires,
				AddedBy:  username,
				AddedAt:  time.Now().Format("2006-01-02"),
			})
			if err := ignores.Save(filePath, f); err != nil {
				return err
			}
			fmt.Printf("✓ Suppression ajoutée dans %s : %s sur %s\n", filePath, ruleID, resource)
			fmt.Println("  Pensez à committer ce fichier en MR pour revue.")
			return nil
		},
	}
	c.Flags().StringVar(&ruleID, "rule", "", "ID de la règle à supprimer (ex: OSC-SG-001)")
	c.Flags().StringVar(&resource, "resource", "", "ID de la ressource concernée (ou * pour toutes)")
	c.Flags().StringVar(&reason, "reason", "", "Raison de la suppression (ticket, ADR, etc.)")
	c.Flags().StringVar(&expires, "expires", "", "Date d'expiration YYYY-MM-DD (recommandé)")
	c.Flags().StringVar(&filePath, "file", "", "Chemin du fichier .osc-policy-ignore (défaut: ./)")
	c.Flags().BoolVar(&list, "list", false, "Lister les suppressions actives")
	return c
}

func listSuppressions(f *ignores.File, path string) error {
	if len(f.Ignores) == 0 {
		fmt.Printf("Aucune suppression dans %s.\n", path)
		return nil
	}
	fmt.Printf("Suppressions actives dans %s :\n\n", path)
	now := time.Now()
	for _, ig := range f.Ignores {
		expired := ""
		if ig.Expires != "" {
			t, err := time.Parse("2006-01-02", ig.Expires)
			if err == nil && now.After(t) {
				expired = " ⚠ EXPIRÉE"
			}
		}
		fmt.Printf("  • %s sur %s%s\n", ig.Rule, ig.Resource, expired)
		fmt.Printf("      raison    : %s\n", ig.Reason)
		if ig.Expires != "" {
			fmt.Printf("      expire    : %s\n", ig.Expires)
		}
		if ig.AddedBy != "" {
			fmt.Printf("      ajouté par: %s (%s)\n", ig.AddedBy, ig.AddedAt)
		}
		_, _ = fmt.Fprintln(os.Stdout)
	}
	return nil
}
