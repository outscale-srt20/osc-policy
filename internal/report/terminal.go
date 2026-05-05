package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type TerminalOptions struct {
	NoColor   bool
	Quiet     bool
	ToolName  string
	Version   string
	Profile   string // profil Rego: security|finops|compliance|all
	Account   string // compte Outscale effectif (scan live uniquement)
	Input     string // plan.json path ou "live:<region>"
	RuleCount int
}

// Palette
var (
	colCritical = lipgloss.Color("#FF4D4F")
	colHigh     = lipgloss.Color("#FF8C42")
	colMedium   = lipgloss.Color("#F2C744")
	colLow      = lipgloss.Color("#4FACF7")
	colInfo     = lipgloss.Color("#9BA3AF")
	colPass     = lipgloss.Color("#5BC976")
	colBrand    = lipgloss.Color("#C792EA")
	colAccent   = lipgloss.Color("#5CCDEF")
	colMuted    = lipgloss.Color("#6C7280")
	colBody     = lipgloss.Color("#D5D8DC")
)

var (
	styleBrand  = lipgloss.NewStyle().Foreground(colBrand).Bold(true)
	styleTitle  = lipgloss.NewStyle().Foreground(colBody).Bold(true)
	styleAccent = lipgloss.NewStyle().Foreground(colAccent)
	styleMuted  = lipgloss.NewStyle().Foreground(colMuted)
	styleValue  = lipgloss.NewStyle().Foreground(colBody)
	styleRule   = lipgloss.NewStyle().Foreground(colMuted)
	stylePass   = lipgloss.NewStyle().Foreground(colPass).Bold(true)
	styleFail   = lipgloss.NewStyle().Foreground(colCritical).Bold(true)
	styleSave   = lipgloss.NewStyle().Foreground(colPass).Bold(true)
	styleCost   = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
)

const hrWidth = 78

func distinctRuleIDs(findings []Finding) int {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Status == "FAILED" && f.RuleID != "" {
			seen[f.RuleID] = true
		}
	}
	return len(seen)
}

func severityColor(s Severity) lipgloss.Color {
	switch s {
	case SeverityCritical:
		return colCritical
	case SeverityHigh:
		return colHigh
	case SeverityMedium:
		return colMedium
	case SeverityLow:
		return colLow
	}
	return colInfo
}

func sevIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🔵"
	}
	return "⚪"
}

func gradeColor(g Grade) lipgloss.Color {
	switch g {
	case GradeA, GradeB:
		return colPass
	case GradeC:
		return colMedium
	case GradeD:
		return colHigh
	case GradeE, GradeF, GradeG:
		return colCritical
	}
	return colBody
}

// gradeLettersASCII contient le rendu ANSI Shadow de chaque grade (A à G).
// Chaque lettre occupe 6 lignes × 9 colonnes — même largeur fixée à l'œil
// pour assurer un alignement parfait du bloc "détails" à droite.
var gradeLettersASCII = map[Grade][]string{
	GradeA: {
		` █████╗  `,
		`██╔══██╗ `,
		`███████║ `,
		`██╔══██║ `,
		`██║  ██║ `,
		`╚═╝  ╚═╝ `,
	},
	GradeB: {
		`██████╗  `,
		`██╔══██╗ `,
		`██████╔╝ `,
		`██╔══██╗ `,
		`██████╔╝ `,
		`╚═════╝  `,
	},
	GradeC: {
		` ██████╗ `,
		`██╔════╝ `,
		`██║      `,
		`██║      `,
		`╚██████╗ `,
		` ╚═════╝ `,
	},
	GradeD: {
		`██████╗  `,
		`██╔══██╗ `,
		`██║  ██║ `,
		`██║  ██║ `,
		`██████╔╝ `,
		`╚═════╝  `,
	},
	GradeE: {
		`███████╗ `,
		`██╔════╝ `,
		`█████╗   `,
		`██╔══╝   `,
		`███████╗ `,
		`╚══════╝ `,
	},
	GradeF: {
		`███████╗ `,
		`██╔════╝ `,
		`█████╗   `,
		`██╔══╝   `,
		`██║      `,
		`╚═╝      `,
	},
	GradeG: {
		` ██████╗ `,
		`██╔════╝ `,
		`██║  ███╗`,
		`██║   ██║`,
		`╚██████╔╝`,
		` ╚═════╝ `,
	},
}

// progressBar rend une barre de progression Unicode de `width` colonnes,
// remplie à hauteur de `pct` %. Retourne une chaîne stylisée avec `fill`
// pour la portion atteinte et gris muted pour le reste.
func progressBar(pct, width int, fill lipgloss.Color) string {
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	filled := width * pct / 100
	empty := width - filled
	return lipgloss.NewStyle().Foreground(fill).Render(strings.Repeat("█", filled)) +
		styleMuted.Render(strings.Repeat("░", empty))
}

func writeScoreBlock(w io.Writer, sc ScanScore) {
	gc := gradeColor(sc.Grade)
	letter := gradeLettersASCII[sc.Grade]
	if letter == nil {
		letter = gradeLettersASCII[GradeG]
	}
	letterStyle := lipgloss.NewStyle().Foreground(gc).Bold(true)

	// Bloc de droite : score, barre, libellé, séparateur, compteurs.
	score := lipgloss.NewStyle().Foreground(gc).Bold(true).
		Render(fmt.Sprintf("%d / 100 pts", sc.Score))
	bar := progressBar(sc.Score, 40, gc)
	label := lipgloss.NewStyle().Foreground(gc).Bold(true).Render(sc.Label)
	counts := fmt.Sprintf(
		"🔴 CRITICAL %d   🟠 HIGH %d   🟡 MEDIUM %d   🔵 LOW %d",
		sc.Counts[SeverityCritical], sc.Counts[SeverityHigh],
		sc.Counts[SeverityMedium], sc.Counts[SeverityLow],
	)

	right := []string{
		"",
		score,
		bar,
		label + styleMuted.Render("  —  note globale du scan"),
		"",
		counts,
	}

	for i := 0; i < 6; i++ {
		_, _ = fmt.Fprintln(w, " "+letterStyle.Render(letter[i])+"  "+right[i])
	}

	if sc.CriticalCapApplied {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, " "+styleFail.Render("▲ Plafond CRITICAL appliqué")+
			styleMuted.Render("  (score ≤ 45 tant qu'un CRITICAL est présent)"))
	}

	if len(sc.Services) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, " "+styleMuted.Render("Par service"))

		headers := []string{"Service", "Score", "Grade", "Fail", "Répartition C·H·M·L"}
		rows := make([][]string, 0, len(sc.Services))
		for _, svc := range sc.Services {
			sg := gradeColor(svc.Grade)
			rows = append(rows, []string{
				serviceLabel(svc.Service),
				lipgloss.NewStyle().Foreground(sg).Render(fmt.Sprintf("%d/100", svc.Score)),
				lipgloss.NewStyle().Foreground(sg).Bold(true).Render(string(svc.Grade)),
				fmt.Sprintf("%d", svc.TotalFail),
				stackedSeverityBar(svc.Counts, 20),
			})
		}
		writeBoxTable(w, " ", headers, rows, []bool{false, true, false, true, false})
	}
}

// serviceLabels convertit le préfixe technique extrait d'un rule_id
// (ex: "KP", "SG") en libellé lisible pour les rapports humains.
var serviceLabels = map[string]string{
	"VM":   "VM",
	"SG":   "Security Group",
	"VOL":  "Volume",
	"NET":  "Net / Subnet",
	"LBU":  "Load Balancer",
	"KP":   "Keypair",
	"KEY":  "Access Key",
	"OOS":  "Object Storage",
	"SNAP": "Snapshot",
	"VPN":  "VPN",
	"TAG":  "Tagging",
	"ACC":  "API Access",
	"EIM":  "EIM Policy",
	"FIN":  "FinOps",
	"NIC":  "Network Interface",
	"IPS":  "Public IP",
}

func serviceLabel(code string) string {
	if l, ok := serviceLabels[code]; ok {
		return l
	}
	return code
}

// stackedSeverityBar rend une barre empilée colorée représentant la répartition
// CRITICAL / HIGH / MEDIUM / LOW. Chaque sévérité présente occupe au minimum
// 1 colonne pour rester visible ; le reste est alloué proportionnellement
// au nombre de findings. La largeur totale reste fixée à `width`.
func stackedSeverityBar(counts map[Severity]int, width int) string {
	order := []struct {
		sev   Severity
		color lipgloss.Color
	}{
		{SeverityCritical, colCritical},
		{SeverityHigh, colHigh},
		{SeverityMedium, colMedium},
		{SeverityLow, colLow},
	}

	total := 0
	for _, s := range order {
		total += counts[s.sev]
	}
	if total == 0 {
		return styleMuted.Render(strings.Repeat("·", width))
	}

	// Attribution proportionnelle avec minimum 1 pour toute sévérité présente.
	segments := make([]int, len(order))
	for i, s := range order {
		n := width * counts[s.sev] / total
		if counts[s.sev] > 0 && n == 0 {
			n = 1
		}
		segments[i] = n
	}

	// Ajuster la somme pour qu'elle colle exactement à width.
	sum := 0
	for _, n := range segments {
		sum += n
	}
	diff := width - sum
	for diff != 0 {
		// Trouve le plus gros segment pour absorber le diff (positif ou négatif).
		idx := -1
		for i, n := range segments {
			if counts[order[i].sev] == 0 {
				continue
			}
			if idx == -1 || n > segments[idx] {
				idx = i
			}
		}
		if idx < 0 {
			break
		}
		if diff > 0 {
			segments[idx]++
			diff--
		} else {
			if segments[idx] > 1 {
				segments[idx]--
				diff++
			} else {
				break
			}
		}
	}

	var b strings.Builder
	for i, s := range order {
		if segments[i] > 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(s.color).
				Render(strings.Repeat("█", segments[i])))
		}
	}
	return b.String()
}

func categoryIcon(c Category) string {
	switch c {
	case CategorySecurity:
		return "🔒"
	case CategoryFinOps:
		return "💰"
	case CategoryCompliance:
		return "📋"
	}
	return "•"
}

// WriteTerminal écrit un rendu riche avec lipgloss : bandeau compact, findings
// regroupés par règle (style Plumber), tableau de synthèse « Controls » et
// bloc de score en tête de résumé.
func WriteTerminal(w io.Writer, r ScanResult, opts TerminalOptions) {
	if opts.NoColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	if !opts.Quiet {
		writeHeader(w, r, opts)
	}

	failed := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Status == "FAILED" {
			failed = append(failed, f)
		}
	}

	if len(failed) == 0 && !opts.Quiet {
		_, _ = fmt.Fprintln(w, "  "+stylePass.Render("✓")+" "+styleValue.Render("Aucun finding — tout est conforme"))
		_, _ = fmt.Fprintln(w)
	} else {
		multiAccount := hasMultipleAccounts(failed)
		if !opts.Quiet {
			writeImmediateActions(w, failed)
		}
		ruleOrder, byRule := groupByRule(failed)
		for _, id := range ruleOrder {
			writeRuleGroup(w, id, byRule[id], multiAccount)
		}
		if !opts.Quiet {
			writeControlsTable(w, ruleOrder, byRule)
		}
	}

	if !opts.Quiet {
		writeSummary(w, r)
	}
}

// ruleGroup agrège les findings partageant le même rule_id pour un rendu
// compact : un seul header, une liste d'occurrences.
type ruleGroup struct {
	RuleID      string
	Title       string
	Severity    Severity
	Category    Category
	Remediation string
	References  []string
	Findings    []Finding
}

// groupByRule partitionne les findings par rule_id. L'ordre retourné classe
// les groupes par sévérité décroissante, puis par rule_id pour un rendu
// stable entre deux scans.
func groupByRule(findings []Finding) ([]string, map[string]*ruleGroup) {
	byRule := map[string]*ruleGroup{}
	for _, f := range findings {
		g, ok := byRule[f.RuleID]
		if !ok {
			g = &ruleGroup{
				RuleID:      f.RuleID,
				Title:       f.RuleTitle,
				Severity:    f.Severity,
				Category:    f.Category,
				Remediation: f.Remediation,
				References:  f.References,
			}
			byRule[f.RuleID] = g
		}
		g.Findings = append(g.Findings, f)
	}
	order := make([]string, 0, len(byRule))
	for id := range byRule {
		order = append(order, id)
	}
	sort.SliceStable(order, func(i, j int) bool {
		si, sj := severityRank(byRule[order[i]].Severity), severityRank(byRule[order[j]].Severity)
		if si != sj {
			return si < sj
		}
		return order[i] < order[j]
	})
	return order, byRule
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	}
	return 4
}

// shortSev retourne la forme courte (4 caractères fixes) utilisée dans les
// listes compactes de findings.
func shortSev(s Severity) string {
	switch s {
	case SeverityCritical:
		return "CRIT"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MED "
	case SeverityLow:
		return "LOW "
	}
	return "INFO"
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func hasMultipleAccounts(findings []Finding) bool {
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Account] = true
		if len(seen) > 1 {
			return true
		}
	}
	return false
}

// writeRuleGroup rend un groupe de findings partageant la même règle, style
// Plumber : bandeau titre encadré de tirets, total, liste compacte, puis
// remédiation en fin de bloc (affichée une seule fois).
func writeRuleGroup(w io.Writer, ruleID string, g *ruleGroup, multiAccount bool) {
	sc := severityColor(g.Severity)
	bar := styleRule.Render(strings.Repeat("─", hrWidth))

	sevTag := lipgloss.NewStyle().Foreground(sc).Bold(true).Render(string(g.Severity))
	catTag := styleMuted.Render(categoryIcon(g.Category) + " " + string(g.Category))
	title := styleTitle.Render(truncate(g.Title, hrWidth-16))

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, bar)
	_, _ = fmt.Fprintln(w, " "+sevTag+styleMuted.Render("  ·  ")+
		styleAccent.Render(ruleID)+styleMuted.Render("  ·  ")+catTag)
	_, _ = fmt.Fprintln(w, " "+title)
	_, _ = fmt.Fprintln(w, bar)

	_, _ = fmt.Fprintln(w, "  "+styleMuted.Render("Total Findings:")+" "+
		lipgloss.NewStyle().Foreground(sc).Bold(true).Render(fmt.Sprintf("%d", len(g.Findings))))
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  "+styleMuted.Render("Issues Found:"))

	for _, f := range g.Findings {
		sev := lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Bold(true).
			Render(shortSev(f.Severity))

		resource := f.ResourceAddress
		if resource == "" {
			resource = f.ResourceID
		}

		_, _ = fmt.Fprintf(w, "      %s  %s — %s\n",
			sev,
			styleValue.Render(resource),
			styleValue.Render(f.Message))

		if multiAccount && f.Account != "" {
			_, _ = fmt.Fprintln(w, "      "+styleMuted.Render("↳ compte: "+f.Account))
		}
		if f.ResourceType != "" {
			_, _ = fmt.Fprintln(w, "      "+styleMuted.Render("↳ type: "+f.ResourceType))
		}
		if f.FilePath != "" {
			_, _ = fmt.Fprintln(w, "      "+styleMuted.Render("↳ at "+f.FilePath))
		}
	}

	if g.Remediation != "" {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "  "+styleMuted.Render("Remédiation"))
		for _, l := range strings.Split(strings.TrimRight(g.Remediation, "\n"), "\n") {
			_, _ = fmt.Fprintln(w, "    "+styleValue.Render(l))
		}
	}

	if len(g.References) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "  "+styleMuted.Render("Références"))
		for _, ref := range g.References {
			_, _ = fmt.Fprintln(w, "    "+styleMuted.Render("• ")+styleValue.Render(ref))
		}
	}
}

// writeControlsTable affiche un tableau récapitulatif style Plumber listant
// chaque règle ayant déclenché, sa sévérité et son nombre d'occurrences.
// Rendu avec des bordures Unicode (╭─┬─╮ / ├─┼─┤ / ╰─┴─╯).
func writeControlsTable(w io.Writer, order []string, byRule map[string]*ruleGroup) {
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  "+styleMuted.Render("Controls"))

	headers := []string{"Control", "Code", "Severity", "#"}
	rows := make([][]string, 0, len(order))
	for _, id := range order {
		g := byRule[id]
		rows = append(rows, []string{
			truncate(g.Title, 55),
			id,
			string(g.Severity),
			fmt.Sprintf("%d", len(g.Findings)),
		})
	}
	rightAlign := []bool{false, false, false, true}
	writeBoxTable(w, "  ", headers, rows, rightAlign)
}

// writeBoxTable rend un tableau avec des bordures Unicode propres. Les colonnes
// sont dimensionnées selon le plus long contenu. rightAlign active l'alignement
// à droite par colonne (typiquement pour les compteurs numériques).
func writeBoxTable(w io.Writer, indent string, headers []string, rows [][]string, rightAlign []bool) {
	ncol := len(headers)
	widths := make([]int, ncol)
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < ncol {
				n := lipgloss.Width(c)
				if n > widths[i] {
					widths[i] = n
				}
			}
		}
	}

	pad := func(s string, i int) string {
		spaces := widths[i] - lipgloss.Width(s)
		if spaces < 0 {
			spaces = 0
		}
		if i < len(rightAlign) && rightAlign[i] {
			return strings.Repeat(" ", spaces) + s
		}
		return s + strings.Repeat(" ", spaces)
	}

	line := func(left, mid, right, fill string) string {
		parts := make([]string, ncol)
		for i, w := range widths {
			parts[i] = strings.Repeat(fill, w+2)
		}
		return indent + styleRule.Render(left+strings.Join(parts, mid)+right)
	}

	row := func(cells []string) string {
		parts := make([]string, ncol)
		for i := 0; i < ncol; i++ {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			parts[i] = " " + pad(c, i) + " "
		}
		sep := styleRule.Render("│")
		return indent + sep + strings.Join(parts, sep) + sep
	}

	_, _ = fmt.Fprintln(w, line("╭", "┬", "╮", "─"))
	_, _ = fmt.Fprintln(w, row(headers))
	_, _ = fmt.Fprintln(w, line("├", "┼", "┤", "─"))
	for _, r := range rows {
		_, _ = fmt.Fprintln(w, row(r))
	}
	_, _ = fmt.Fprintln(w, line("╰", "┴", "╯", "─"))
}

// bannerLines est le logo ASCII « osc-policy » affiché en tête de chaque run.
// Style ANSI Shadow — tient dans 78 colonnes.
var bannerLines = []string{
	` ██████╗ ███████╗ ██████╗     ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗`,
	`██╔═══██╗██╔════╝██╔════╝     ██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝`,
	`██║   ██║███████╗██║          ██████╔╝██║   ██║██║     ██║██║      ╚████╔╝ `,
	`██║   ██║╚════██║██║          ██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝  `,
	`╚██████╔╝███████║╚██████╗     ██║     ╚██████╔╝███████╗██║╚██████╗   ██║   `,
	` ╚═════╝ ╚══════╝ ╚═════╝     ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝   `,
}

// WriteStartupBanner écrit le logo ASCII « osc-policy » et la tagline dès le
// démarrage d'une commande de scan, avant toute collecte ou évaluation OPA.
// Typiquement appelée sur os.Stderr pour ne pas polluer un stdout capturé
// (exports JSON / SARIF / JUnit).
func WriteStartupBanner(w io.Writer, version string, noColor, quiet bool) {
	if quiet {
		return
	}
	if noColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	_, _ = fmt.Fprintln(w)
	for _, l := range bannerLines {
		_, _ = fmt.Fprintln(w, " "+styleBrand.Render(l))
	}
	tagline := styleMuted.Render("v"+version) +
		"  " + styleAccent.Render("· Outscale Security, Compliance & FinOps Scanner")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, " "+tagline)
	_, _ = fmt.Fprintln(w)
}

func writeHeader(w io.Writer, r ScanResult, opts TerminalOptions) {
	_, _ = fmt.Fprintln(w, styleRule.Render(strings.Repeat("─", hrWidth)))
	_, _ = fmt.Fprintln(w, metaLine("Mode", r.ScanMode))
	_, _ = fmt.Fprintln(w, metaLine("Source", opts.Input))
	if opts.Account != "" {
		_, _ = fmt.Fprintln(w, metaLine("Compte", opts.Account))
	}
	_, _ = fmt.Fprintln(w, metaLine("Policies", opts.Profile))
	_, _ = fmt.Fprintln(w, metaLine("Règles", fmt.Sprintf("%d chargées", opts.RuleCount)))
	_, _ = fmt.Fprintln(w, styleRule.Render(strings.Repeat("─", hrWidth)))
	_, _ = fmt.Fprintln(w)
}

func metaLine(label, value string) string {
	return " " + styleMuted.Render(fmt.Sprintf("%-8s", label)) + "  " + styleValue.Render(value)
}

func writeSummary(w io.Writer, r ScanResult) {
	s := r.Summary
	sep := styleRule.Render(strings.Repeat("─", hrWidth))

	_, _ = fmt.Fprintln(w, sep)
	_, _ = fmt.Fprintln(w, " "+styleBrand.Render("Résumé"))
	_, _ = fmt.Fprintln(w)

	if r.Score != nil {
		writeScoreBlock(w, *r.Score)
		_, _ = fmt.Fprintln(w)
	}

	chip := func(icon, label string, n int, c lipgloss.Color) string {
		num := lipgloss.NewStyle().Foreground(c).Bold(true).Render(fmt.Sprintf("%d", n))
		return icon + " " + styleMuted.Render(label) + " " + num
	}

	rulesFired := distinctRuleIDs(r.Findings)
	_, _ = fmt.Fprintln(w, " "+styleMuted.Render("Findings")+"         "+
		lipgloss.NewStyle().Foreground(colCritical).Bold(true).Render(fmt.Sprintf("%d", s.Failed))+
		styleMuted.Render(fmt.Sprintf("  (issus de %d règles)", rulesFired)))

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, " "+styleMuted.Render("Par catégorie"))
	_, _ = fmt.Fprintln(w, " "+
		chip("🔒", "Security", s.ByCategory[CategorySecurity], colAccent)+"  "+
		chip("💰", "FinOps", s.ByCategory[CategoryFinOps], colMedium)+"  "+
		chip("📋", "Compliance", s.ByCategory[CategoryCompliance], colBrand))

	if s.TotalMonthlyCost > 0 || s.TotalPotentialSavings > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, " "+styleMuted.Render(fmt.Sprintf("%-22s", "Coût mensuel estimé"))+"  "+
			styleCost.Render(fmt.Sprintf("%10.2f €", s.TotalMonthlyCost)))
		_, _ = fmt.Fprintln(w, " "+styleMuted.Render(fmt.Sprintf("%-22s", "Économies potentielles"))+"  "+
			styleSave.Render(fmt.Sprintf("%10.2f €", s.TotalPotentialSavings)))
	}

	_, _ = fmt.Fprintln(w, sep)
}

// writeImmediateActions affiche en tête de rapport les 3 findings les plus
// critiques avec une commande de remédiation copy-pastable, pour donner à
// l'utilisateur une porte d'entrée actionnable plutôt qu'un mur de findings.
func writeImmediateActions(w io.Writer, findings []Finding) {
	// Trie : CRITICAL d'abord, puis HIGH, puis le reste
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	top := sorted
	if len(top) > 3 {
		top = top[:3]
	}

	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

	sep := strings.Repeat("─", 78)
	_, _ = fmt.Fprintln(w, sep)
	_, _ = fmt.Fprintln(w, " "+header.Render("⚡ Action immédiate — top 3 findings critiques"))
	_, _ = fmt.Fprintln(w, sep)
	_, _ = fmt.Fprintln(w)

	for i, f := range top {
		sevTag := sevIcon(f.Severity) + " " + shortSev(f.Severity)
		_, _ = fmt.Fprintf(w, "  %d. %s  %s — %s\n", i+1, sevTag, lipgloss.NewStyle().Bold(true).Render(f.RuleID), truncate(f.RuleTitle, 60))
		if f.ResourceAddress != "" {
			_, _ = fmt.Fprintf(w, "     %s %s\n", dim.Render("ressource :"), f.ResourceAddress)
		}
		_, _ = fmt.Fprintf(w, "     %s %s\n", dim.Render("explain   :"), cmd.Render("osc-policy explain "+f.RuleID))
		if f.ResourceID != "" {
			_, _ = fmt.Fprintf(w, "     %s %s\n", dim.Render("fix       :"), cmd.Render(fmt.Sprintf("osc-policy fix --rule %s --resource %s", f.RuleID, f.ResourceID)))
		}
		_, _ = fmt.Fprintln(w)
	}
}
