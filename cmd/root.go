package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/config"
	"github.com/outscale-srt20/osc-policy/version"
)

// GlobalFlags regroupe les flags globaux du CLI.
type GlobalFlags struct {
	ConfigPath string
	Output     string
	Severity   string
	Profile    string
	PolicyDir  string
	SkipRules  []string
	TagFilter  []string
	NoColor    bool
	Quiet      bool
	FailOn     string
	MinGrade   string
	Debug      bool
}

var gflags = &GlobalFlags{}

// updateCh reçoit le résultat du check de mise à jour (lancé en goroutine).
var updateCh = make(chan *version.CheckResult, 1)

var rootCmd = &cobra.Command{
	Use:   "osc-policy",
	Short: "Scanner de sécurité et FinOps pour Outscale",
	Long: `osc-policy est un scanner de conformité et de sécurité pour les ressources
Outscale IaaS. Il analyse les plans Terraform (pré-déploiement) et les
ressources live via l'API Outscale (post-déploiement), à l'aide de règles
Rego évaluées par le moteur OPA embarqué.`,
	Version:       version.Version,
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		go func() {
			updateCh <- version.CheckLatest(context.Background())
		}()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		result := <-updateCh
		if result != nil && result.Newer {
			fmt.Fprintf(os.Stderr, "\n⚡ Nouvelle version disponible : v%s (actuelle : v%s)\n", result.Latest, result.Current)
			fmt.Fprintf(os.Stderr, "   mise use --global github:outscale-srt20/osc-policy@v%s\n\n", result.Latest)
		}
	},
}

// Execute exécute la commande racine.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&gflags.ConfigPath, "config", "", "Fichier de configuration (.osc-policy.yaml)")
	rootCmd.PersistentFlags().StringVarP(&gflags.Output, "output", "o", "terminal", "Format de sortie: terminal|json|sarif|junit|markdown")
	rootCmd.PersistentFlags().StringVar(&gflags.Severity, "severity", "LOW", "Sévérité minimale à reporter")
	rootCmd.PersistentFlags().StringVar(&gflags.Profile, "profile", "all", "Profil: security|finops|compliance|all")
	rootCmd.PersistentFlags().StringVar(&gflags.PolicyDir, "policy", "", "Répertoire de policies additionnelles")
	rootCmd.PersistentFlags().StringSliceVar(&gflags.SkipRules, "skip-rule", nil, "IDs de règles à ignorer")
	rootCmd.PersistentFlags().StringSliceVar(&gflags.TagFilter, "tag-filter", nil, "Filtrer ressources par tag (ex: Env=prod)")
	rootCmd.PersistentFlags().BoolVar(&gflags.NoColor, "no-color", false, "Désactiver les couleurs terminal")
	rootCmd.PersistentFlags().BoolVarP(&gflags.Quiet, "quiet", "q", false, "Afficher seulement les findings")
	rootCmd.PersistentFlags().StringVar(&gflags.FailOn, "fail-on", "HIGH", "Sévérité qui déclenche un code retour non-zéro")
	rootCmd.PersistentFlags().StringVar(&gflags.MinGrade, "min-grade", "", "Grade minimal requis (A-G) ; en dessous, code retour non-zéro")
	rootCmd.PersistentFlags().BoolVar(&gflags.Debug, "debug", false, "Mode debug OPA")

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(rulesCmd())
	rootCmd.AddCommand(docsCmd())
	rootCmd.AddCommand(explainCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(fixCmd())
	rootCmd.AddCommand(suppressCmd())
	rootCmd.AddCommand(diffCmd())
	rootCmd.AddCommand(reportCmd())

	registerGlobalCompletions(rootCmd)
	registerSubcommandCompletions(rootCmd)
}

// loadConfig charge la config + fusionne les flags CLI.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(gflags.ConfigPath)
	if err != nil {
		return nil, err
	}
	if gflags.Profile != "" {
		cfg.Scan.Profile = gflags.Profile
	}
	if gflags.Severity != "" {
		cfg.Scan.MinSeverity = gflags.Severity
	}
	if gflags.FailOn != "" {
		cfg.Scan.FailOn = gflags.FailOn
	}
	if gflags.MinGrade != "" {
		cfg.Scan.MinGrade = gflags.MinGrade
	}
	if gflags.Output != "" {
		cfg.Scan.Output = gflags.Output
	}
	if len(gflags.SkipRules) > 0 {
		cfg.Scan.SkipRules = append(cfg.Scan.SkipRules, gflags.SkipRules...)
	}
	if gflags.PolicyDir != "" {
		cfg.Policies.ExtraDir = gflags.PolicyDir
	}
	return cfg, nil
}
