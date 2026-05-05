package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config représente la configuration globale de l'outil.
type Config struct {
	Outscale OutscaleConfig `mapstructure:"outscale"`
	Scan     ScanConfig     `mapstructure:"scan"`
	Policies PoliciesConfig `mapstructure:"policies"`
	FinOps   FinOpsConfig   `mapstructure:"finops"`
	Docs     DocsConfig     `mapstructure:"docs"`
}

type OutscaleConfig struct {
	Region       string `mapstructure:"region"`
	AccessKeyID  string `mapstructure:"access_key_id"`
	SecretKeyID  string `mapstructure:"secret_key_id"`
}

type ScanConfig struct {
	Profile     string            `mapstructure:"profile"`
	MinSeverity string            `mapstructure:"min_severity"`
	FailOn      string            `mapstructure:"fail_on"`
	MinGrade    string            `mapstructure:"min_grade"`
	SkipRules   []string          `mapstructure:"skip_rules"`
	Output      string            `mapstructure:"output"`
	TagFilter   map[string]string `mapstructure:"tag_filter"`
}

type PoliciesConfig struct {
	ExtraDir string `mapstructure:"extra_dir"`
}

type FinOpsConfig struct {
	MonthlyBudget  float64 `mapstructure:"monthly_budget"`
	CostEstimation bool    `mapstructure:"cost_estimation"`
	PricesFile     string  `mapstructure:"prices_file"`
}

type DocsConfig struct {
	OutputDir string `mapstructure:"output_dir"`
	Format    string `mapstructure:"format"`
	Lang      string `mapstructure:"lang"`
}

// Defaults renvoie une configuration par défaut.
func Defaults() *Config {
	return &Config{
		Outscale: OutscaleConfig{Region: "eu-west-2"},
		Scan: ScanConfig{
			Profile:     "all",
			MinSeverity: "LOW",
			FailOn:      "HIGH",
			Output:      "terminal",
		},
		FinOps: FinOpsConfig{CostEstimation: true},
		Docs:   DocsConfig{OutputDir: "./docs/rules", Format: "markdown", Lang: "fr"},
	}
}

// Load charge la configuration depuis un fichier (facultatif) + variables d'env.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("OSC_POLICY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("lecture config %s: %w", path, err)
		}
	}

	// Surcharger avec les variables Outscale standards
	if k := viper.GetString("OUTSCALE_ACCESSKEYID"); k != "" {
		cfg.Outscale.AccessKeyID = k
	}

	if v.ConfigFileUsed() != "" {
		if err := v.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}

	return cfg, nil
}
