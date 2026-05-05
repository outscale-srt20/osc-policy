package report

import (
	"sort"
	"strings"
)

// Grade représente la note agrégée d'un scan (A = excellent, G = critique).
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeE Grade = "E"
	GradeF Grade = "F"
	GradeG Grade = "G"
)

// Barème de pénalités additives appliqué à chaque finding FAILED.
var penaltyWeights = map[Severity]int{
	SeverityCritical: 30,
	SeverityHigh:     10,
	SeverityMedium:   3,
	SeverityLow:      1,
}

// Plafond du score quand au moins un CRITICAL est présent (grade E max).
const criticalScoreCap = 45

// gradeThreshold retourne le grade correspondant au score. Ordre décroissant
// respecté pour un premier-match rapide.
var gradeThresholds = []struct {
	min   int
	grade Grade
}{
	{91, GradeA},
	{76, GradeB},
	{61, GradeC},
	{46, GradeD},
	{31, GradeE},
	{16, GradeF},
	{0, GradeG},
}

var gradeLabels = map[Grade]string{
	GradeA: "Excellent",
	GradeB: "Bon",
	GradeC: "Passable",
	GradeD: "Insuffisant",
	GradeE: "Mauvais",
	GradeF: "Très mauvais",
	GradeG: "Critique",
}

// ServiceScore agrège le score d'un service (VM, SG, OOS, …).
type ServiceScore struct {
	Service     string           `json:"service"`
	Score       int              `json:"score"`
	Grade       Grade            `json:"grade"`
	Counts      map[Severity]int `json:"counts"`
	TotalFail   int              `json:"total_fail"`
	TotalPass   int              `json:"total_pass"`
	TotalChecks int              `json:"total_checks"`
}

// ScanScore agrège le score global d'un scan plus le détail par service.
type ScanScore struct {
	Score               int              `json:"score"`
	Grade               Grade            `json:"grade"`
	Label               string           `json:"label"`
	Counts              map[Severity]int `json:"counts"`
	TotalFail           int              `json:"total_fail"`
	TotalPass           int              `json:"total_pass"`
	TotalError          int              `json:"total_error"`
	TotalChecks         int              `json:"total_checks"`
	Services            []ServiceScore   `json:"services"`
	CriticalCapApplied  bool             `json:"critical_cap_applied"`
}

// PassRate retourne le taux de passage (0-100) arrondi à une décimale.
func (s ScanScore) PassRate() float64 {
	if s.TotalChecks == 0 {
		return 0
	}
	return roundOne(float64(s.TotalPass) / float64(s.TotalChecks) * 100)
}

// PassRate retourne le taux de passage du service.
func (s ServiceScore) PassRate() float64 {
	if s.TotalChecks == 0 {
		return 0
	}
	return roundOne(float64(s.TotalPass) / float64(s.TotalChecks) * 100)
}

func roundOne(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// ComputeScore calcule le score global et par service à partir des findings.
//
// Règles :
//   - pénalités additives : CRITICAL=30, HIGH=10, MEDIUM=3, LOW=1
//   - plancher : score ≥ 0
//   - malus bloquant : ≥ 1 CRITICAL plafonne le score à 45 (grade E ou pire)
func ComputeScore(findings []Finding) ScanScore {
	global := computeSlice(findings)

	bySvc := map[string][]Finding{}
	for _, f := range findings {
		svc := serviceFromRuleID(f.RuleID)
		bySvc[svc] = append(bySvc[svc], f)
	}
	services := make([]ServiceScore, 0, len(bySvc))
	for svc, items := range bySvc {
		score, _ := penaltyScore(countFailedBySeverity(items))
		services = append(services, ServiceScore{
			Service:     svc,
			Score:       score,
			Grade:       scoreToGrade(score),
			Counts:      countFailedBySeverity(items),
			TotalFail:   countStatus(items, "FAILED"),
			TotalPass:   countStatus(items, "PASSED"),
			TotalChecks: len(items),
		})
	}
	sort.SliceStable(services, func(i, j int) bool {
		if services[i].Score != services[j].Score {
			return services[i].Score < services[j].Score
		}
		return services[i].Service < services[j].Service
	})

	return ScanScore{
		Score:              global.score,
		Grade:              scoreToGrade(global.score),
		Label:              gradeLabels[scoreToGrade(global.score)],
		Counts:             global.counts,
		TotalFail:          countStatus(findings, "FAILED"),
		TotalPass:          countStatus(findings, "PASSED"),
		TotalError:         countStatus(findings, "ERROR"),
		TotalChecks:        len(findings),
		Services:           services,
		CriticalCapApplied: global.cap,
	}
}

type globalScore struct {
	score  int
	counts map[Severity]int
	cap    bool
}

func computeSlice(findings []Finding) globalScore {
	counts := countFailedBySeverity(findings)
	score, cap := penaltyScore(counts)
	return globalScore{score: score, counts: counts, cap: cap}
}

func countFailedBySeverity(findings []Finding) map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0, SeverityHigh: 0, SeverityMedium: 0,
		SeverityLow: 0, SeverityInfo: 0,
	}
	for _, f := range findings {
		if f.Status == "FAILED" {
			counts[f.Severity]++
		}
	}
	return counts
}

func countStatus(findings []Finding, status string) int {
	n := 0
	for _, f := range findings {
		if f.Status == status {
			n++
		}
	}
	return n
}

func penaltyScore(counts map[Severity]int) (int, bool) {
	raw := 100
	for sev, weight := range penaltyWeights {
		raw -= counts[sev] * weight
	}
	if raw < 0 {
		raw = 0
	}
	cap := counts[SeverityCritical] > 0
	if cap && raw > criticalScoreCap {
		raw = criticalScoreCap
	}
	return raw, cap
}

func scoreToGrade(score int) Grade {
	for _, t := range gradeThresholds {
		if score >= t.min {
			return t.grade
		}
	}
	return GradeG
}

// gradeRank associe chaque grade à un rang (A=0, G=6). Un grade plus élevé
// (au sens numérique) est une note plus mauvaise.
var gradeRank = map[Grade]int{
	GradeA: 0, GradeB: 1, GradeC: 2, GradeD: 3,
	GradeE: 4, GradeF: 5, GradeG: 6,
}

// MeetsGradeThreshold retourne true si `got` est au moins aussi bon que `min`.
// Ex : got=B, min=A → false. got=A, min=B → true.
// Si min est vide ou invalide, retourne true (seuil désactivé).
func MeetsGradeThreshold(got, min Grade) bool {
	if min == "" {
		return true
	}
	gRank, gOK := gradeRank[got]
	mRank, mOK := gradeRank[min]
	if !gOK || !mOK {
		return true
	}
	return gRank <= mRank
}

// serviceFromRuleID extrait le tronc d'un rule ID. "OSC-VM-001" → "VM",
// "OSC-FIN-003" → "FIN". Retourne "OTHER" si le format ne correspond pas.
func serviceFromRuleID(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) >= 3 && parts[0] == "OSC" {
		return parts[1]
	}
	return "OTHER"
}
