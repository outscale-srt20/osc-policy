package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// fixCmd génère des suggestions de remédiation concrètes (commandes oapi-cli
// ou patches Terraform) pour une règle donnée.
//
// Pour rester simple et sûr, ce mode est exclusivement --dry-run : il
// n'applique jamais les changements, il propose le code à copier-coller.
func fixCmd() *cobra.Command {
	var (
		ruleID   string
		resource string
	)

	c := &cobra.Command{
		Use:   "fix",
		Short: "Suggère une commande de remédiation pour une règle (toujours en dry-run)",
		Long: `Génère un patch Terraform ou une commande oapi-cli pour corriger un
finding identifié. Cette commande N'APPLIQUE JAMAIS les changements — elle
affiche uniquement le code à copier-coller, à valider en MR, puis appliquer.

Exemple :
  osc-policy fix --rule OSC-SG-001 --resource sg-12345678
  osc-policy fix --rule OSC-OKS-001 --resource pentest-fresh`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ruleID == "" {
				return fmt.Errorf("--rule requis (ex: --rule OSC-SG-001)")
			}
			ruleID = strings.ToUpper(ruleID)

			// Validate rule exists
			meta, err := findRuleByID(ruleID)
			if err != nil {
				return err
			}

			tmpl, ok := remediationTemplates[ruleID]
			if !ok {
				_, _ = fmt.Fprintln(os.Stdout)
				_, _ = fmt.Fprintf(os.Stdout, "Pas de template d'auto-remédiation pour %s.\n", ruleID)
				_, _ = fmt.Fprintf(os.Stdout, "Consulter la remédiation textuelle :\n  osc-policy explain %s\n\n", ruleID)
				return nil
			}

			renderFix(meta, tmpl, resource)
			return nil
		},
	}
	c.Flags().StringVar(&ruleID, "rule", "", "ID de la règle à remédier (ex: OSC-SG-001)")
	c.Flags().StringVar(&resource, "resource", "<resource-id>", "ID de la ressource concernée")
	return c
}

// remediationTemplate décrit comment remédier une règle via un patch Terraform
// ou une commande CLI. Le template est une string avec un seul placeholder
// %s pour l'ID de la ressource.
type remediationTemplate struct {
	Title  string
	Format string // "bash" ou "hcl"
	Body   string
}

var remediationTemplates = map[string]remediationTemplate{
	"OSC-KEY-001": {
		Title:  "Définir une expiration sur l'access key",
		Format: "bash",
		Body: `# 1. Créer une nouvelle clé avec expiration à 90 jours
oapi-cli CreateAccessKey --UserName <user> \
  --ExpirationDate $(date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ)

# 2. Migrer les usages vers la nouvelle clé.

# 3. Supprimer l'ancienne (sans expiration) :
oapi-cli DeleteAccessKey --AccessKeyId %s
`,
	},
	"OSC-SG-001": {
		Title:  "Restreindre le port sensible au CIDR du bastion",
		Format: "hcl",
		Body: `# Remplacer la rule ip_range = "0.0.0.0/0" par une référence SG bastion :

resource "outscale_security_group_rule" "ssh_via_bastion" {
  flow              = "Inbound"
  security_group_id = "%s"
  rules {
    from_port_range = "22"
    to_port_range   = "22"
    ip_protocol     = "tcp"
    security_groups_members {
      security_group_id = outscale_security_group.bastion.security_group_id
    }
  }
}
`,
	},
	"OSC-SG-002": {
		Title:  "Remplacer ip_protocol = -1 par un protocole + port précis",
		Format: "hcl",
		Body: `resource "outscale_security_group_rule" "specific" {
  flow              = "Inbound"
  security_group_id = "%s"
  from_port_range   = 443     # port précis
  to_port_range     = 443
  ip_protocol       = "tcp"   # protocole précis
  ip_range          = "10.0.0.0/16"  # source précise
}
`,
	},
	"OSC-OKS-001": {
		Title:  "Restreindre admin_whitelist du cluster OKS",
		Format: "bash",
		Body: `# Mettre à jour la whitelist du cluster (depuis oks-cli) :
oks-cli cluster update -c %s -a "<bastion-ip>/32,<ci-runner-ip>/32"

# Ou via Terraform :
#   resource "outscale_oks_cluster" "c" {
#     admin_whitelist = ["<bastion-ip>/32", "<ci-runner-ip>/32"]
#   }
`,
	},
	"OSC-OKS-002": {
		Title:  "Migrer vers cp.3.masters.small (multi-master)",
		Format: "hcl",
		Body: `# Recréer le cluster avec un control plane multi-master.
# Note: control_planes n'est généralement pas modifiable in-place — recreate
# du cluster nécessaire (migration via blue-green des workloads).

resource "outscale_oks_cluster" "c" {
  name           = "%s-v2"
  control_planes = "cp.3.masters.small"
  cp_multi_az    = true
  # ... reste de la config
}
`,
	},
	"OSC-OOS-001": {
		Title:  "Rendre le bucket OOS privé",
		Format: "bash",
		Body: `aws s3api put-bucket-acl \
  --endpoint-url https://oos.eu-west-2.outscale.com \
  --bucket %s \
  --acl private
`,
	},
	"OSC-OOS-002": {
		Title:  "Activer le versioning sur le bucket",
		Format: "bash",
		Body: `aws s3api put-bucket-versioning \
  --endpoint-url https://oos.eu-west-2.outscale.com \
  --bucket %s \
  --versioning-configuration Status=Enabled
`,
	},
	"OSC-FIN-001": {
		Title:  "Supprimer l'EIP orpheline",
		Format: "bash",
		Body: `# Vérifier qu'aucun script en cours ne va l'attacher :
oapi-cli ReadPublicIps '--Filters.PublicIpIds[]' %s

# Puis supprimer :
oapi-cli DeletePublicIp --PublicIp <ip>  # ou --PublicIpId %s
`,
	},
	"OSC-FIN-002": {
		Title:  "Supprimer le volume BSU détaché",
		Format: "bash",
		Body: `# 1. Vérifier l'état (state doit être "available", pas "in-use") :
oapi-cli ReadVolumes '--Filters.VolumeIds[]' %s

# 2. Snapshot de précaution :
oapi-cli CreateSnapshot --VolumeId %s --Description "pre-delete-$(date +%%F)"

# 3. Supprimer le volume :
oapi-cli DeleteVolume --VolumeId %s
`,
	},
	"OSC-NIC-001": {
		Title:  "Supprimer la NIC orpheline",
		Format: "bash",
		Body: `# Confirmer absence d'usage :
oapi-cli ReadNics '--Filters.NicIds[]' %s

# Supprimer :
oapi-cli DeleteNic --NicId %s
`,
	},
}

func renderFix(meta interface{}, tmpl remediationTemplate, resource string) {
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))

	fmt.Println()
	fmt.Println(header.Render("─── Suggestion de remédiation (DRY-RUN) ───────────────────────────"))
	fmt.Println()
	fmt.Printf("  %s\n", tmpl.Title)
	fmt.Println()

	fmt.Println(dim.Render("  ```" + tmpl.Format))
	body := tmpl.Body
	// Replace all %s with resource (multiple occurrences supported via simple Sprintf chain)
	count := strings.Count(body, "%s")
	args := make([]interface{}, count)
	for i := range args {
		args[i] = resource
	}
	rendered := fmt.Sprintf(body, args...)
	for _, line := range strings.Split(rendered, "\n") {
		fmt.Println("  " + line)
	}
	fmt.Println(dim.Render("  ```"))
	fmt.Println()

	fmt.Println(warn.Render("  ⚠ Cette suggestion N'EST PAS appliquée automatiquement."))
	fmt.Println("    Valider en MR (provider Terraform) ou tester en non-prod avant prod.")
	fmt.Println()
}
