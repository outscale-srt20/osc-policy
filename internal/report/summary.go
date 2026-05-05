package report

import (
	"fmt"
	"io"
	"sort"
)

// PrintSummary affiche un résumé texte simple (utilisé par quiet mode).
func PrintSummary(w io.Writer, r ScanResult) {
	fmt.Fprintf(w, "Total: %d | Failed: %d | Passed: %d | Skipped: %d\n",
		r.Summary.Total, r.Summary.Failed, r.Summary.Passed, r.Summary.Skipped)

	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for _, s := range severities {
		if n := r.Summary.BySeverity[s]; n > 0 {
			fmt.Fprintf(w, "  %s: %d\n", s, n)
		}
	}
}

// SortFindings trie les findings par sévérité décroissante puis par RuleID.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := SeverityRank(findings[i].Severity), SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ResourceAddress < findings[j].ResourceAddress
	})
}
