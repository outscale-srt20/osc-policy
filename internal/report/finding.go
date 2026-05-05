package report

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Category string

const (
	CategorySecurity   Category = "security"
	CategoryFinOps     Category = "finops"
	CategoryCompliance Category = "compliance"
)

type Source string

const (
	SourcePlan Source = "plan"
	SourceLive Source = "live"
)

type Finding struct {
	RuleID    string `json:"rule_id"`
	RuleTitle string `json:"rule_title"`

	Severity Severity `json:"severity"`
	Category Category `json:"category"`

	ResourceID      string `json:"resource_id"`
	ResourceType    string `json:"resource_type"`
	ResourceAddress string `json:"resource_address,omitempty"`
	Region          string `json:"region,omitempty"`
	Account         string `json:"account,omitempty"` // profil/compte Outscale (scan live multi-profils)

	Message     string `json:"message"`
	Description string `json:"description,omitempty"`

	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	Source Source `json:"source"`

	FilePath string `json:"file_path,omitempty"`

	Status string `json:"status"`

	EstimatedMonthlyCost    float64 `json:"estimated_monthly_cost,omitempty"`
	PotentialMonthlySavings float64 `json:"potential_monthly_savings,omitempty"`

	Tags      map[string]string `json:"tags,omitempty"`
	Timestamp time.Time         `json:"timestamp"`

	NoncompliantExample string `json:"-"`
	CompliantExample    string `json:"-"`
}

type Summary struct {
	Total   int `json:"total"`
	Failed  int `json:"failed"`
	Passed  int `json:"passed"`
	Skipped int `json:"skipped"`

	BySeverity map[Severity]int `json:"by_severity"`
	ByCategory map[Category]int `json:"by_category"`
	ByResource map[string]int   `json:"by_resource_type"`

	TotalMonthlyCost      float64 `json:"total_monthly_cost,omitempty"`
	TotalPotentialSavings float64 `json:"total_potential_savings,omitempty"`
}

type ScanResult struct {
	Summary     Summary    `json:"summary"`
	Score       *ScanScore `json:"score,omitempty"`
	Findings    []Finding  `json:"findings"`
	ScanDate    time.Time  `json:"scan_date"`
	ScanMode    string     `json:"scan_mode"`
	Region      string     `json:"region,omitempty"`
	PlanFile    string     `json:"plan_file,omitempty"`
	ToolVersion string     `json:"tool_version"`
}

// SeverityRank donne l'ordre numérique des sévérités pour tri/comparaison.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// MeetsThreshold renvoie true si la sévérité du finding atteint min.
func MeetsThreshold(s Severity, min Severity) bool {
	return SeverityRank(s) >= SeverityRank(min)
}

// BuildSummary calcule le Summary à partir des findings.
func BuildSummary(findings []Finding) Summary {
	sum := Summary{
		BySeverity: make(map[Severity]int),
		ByCategory: make(map[Category]int),
		ByResource: make(map[string]int),
	}
	for _, f := range findings {
		sum.Total++
		switch f.Status {
		case "FAILED":
			sum.Failed++
		case "PASSED":
			sum.Passed++
		case "SKIPPED":
			sum.Skipped++
		}
		if f.Status == "FAILED" {
			sum.BySeverity[f.Severity]++
			sum.ByCategory[f.Category]++
			if f.ResourceType != "" {
				sum.ByResource[f.ResourceType]++
			}
		}
		sum.TotalMonthlyCost += f.EstimatedMonthlyCost
		sum.TotalPotentialSavings += f.PotentialMonthlySavings
	}
	return sum
}
