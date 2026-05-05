package report

import (
	"encoding/xml"
	"fmt"
	"io"
)

type junitTestsuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Testsuites []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string         `xml:"name,attr"`
	Classname string         `xml:"classname,attr"`
	Failure   *junitFailure  `xml:"failure,omitempty"`
	Skipped   *junitSkipped  `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit écrit un rapport JUnit XML.
func WriteJUnit(w io.Writer, r ScanResult) error {
	suites := map[string]*junitTestsuite{}

	for _, f := range r.Findings {
		cat := string(f.Category)
		if cat == "" {
			cat = "default"
		}
		ts, ok := suites[cat]
		if !ok {
			ts = &junitTestsuite{Name: cat}
			suites[cat] = ts
		}
		ts.Tests++

		tc := junitTestcase{
			Name:      fmt.Sprintf("%s on %s", f.RuleID, f.ResourceAddress),
			Classname: f.RuleID,
		}
		switch f.Status {
		case "FAILED":
			ts.Failures++
			tc.Failure = &junitFailure{
				Message: f.Message,
				Type:    string(f.Severity),
				Text:    f.Remediation,
			}
		case "SKIPPED":
			tc.Skipped = &junitSkipped{Message: "skipped"}
		}
		ts.Testcases = append(ts.Testcases, tc)
	}

	root := junitTestsuites{Name: "osc-policy"}
	for _, ts := range suites {
		root.Tests += ts.Tests
		root.Failures += ts.Failures
		root.Testsuites = append(root.Testsuites, *ts)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
