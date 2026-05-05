package cmd

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/outscale-srt20/osc-policy/internal/collector"
	"github.com/outscale-srt20/osc-policy/internal/docgen"
	"github.com/outscale-srt20/osc-policy/internal/engine"
)

var (
	completionSeverities = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	completionProfiles   = []string{"security", "finops", "compliance", "all"}
	completionOutputs    = []string{"terminal", "json", "sarif", "junit", "markdown"}
	completionCollectors = []string{
		"vms", "volumes", "sgs", "ips", "lbus", "nets", "vpn",
		"nics", "snapshots", "images", "keys", "access", "oos", "account", "eim", "all",
	}
)

// completeEnum renvoie une complétion à partir d'une liste fixe.
func completeEnum(values []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeRuleIDs charge les policies embarquées et retourne les IDs de règles.
func completeRuleIDs(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	embedded, err := engine.LoadEmbedded()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	ids := make([]string, 0, len(embedded.Modules))
	for path, src := range embedded.Modules {
		if strings.HasSuffix(path, "_test.rego") {
			continue
		}
		meta, err := docgen.ParseRegoMetadata(path, src)
		if err != nil || meta.ID == "" {
			continue
		}
		ids = append(ids, meta.ID)
	}
	sort.Strings(ids)
	return ids, cobra.ShellCompDirectiveNoFileComp
}

// completeOSCProfiles liste les profils du fichier ~/.osc/config.json.
func completeOSCProfiles(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	all, err := collector.LoadAllOSCProfiles()
	if err != nil || len(all) == 0 {
		return []string{"all"}, cobra.ShellCompDirectiveNoFileComp
	}
	names := make([]string, 0, len(all)+1)
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	names = append(names, "all")
	return names, cobra.ShellCompDirectiveNoFileComp
}

// completeJSONFile restreint la complétion aux fichiers .json.
func completeJSONFile(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) >= 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []string{"json"}, cobra.ShellCompDirectiveFilterFileExt
}

// registerGlobalCompletions attache les complétions aux flags persistents.
func registerGlobalCompletions(c *cobra.Command) {
	_ = c.RegisterFlagCompletionFunc("severity", completeEnum(completionSeverities))
	_ = c.RegisterFlagCompletionFunc("fail-on", completeEnum(completionSeverities))
	_ = c.RegisterFlagCompletionFunc("profile", completeEnum(completionProfiles))
	_ = c.RegisterFlagCompletionFunc("output", completeEnum(completionOutputs))
	_ = c.RegisterFlagCompletionFunc("skip-rule", completeRuleIDs)
	_ = c.RegisterFlagCompletionFunc("policy", completeEnum(nil))
}

// registerSubcommandCompletions attache les complétions spécifiques aux sous-commandes.
func registerSubcommandCompletions(root *cobra.Command) {
	walk(root, func(c *cobra.Command) {
		if c.Flag("collectors") != nil {
			_ = c.RegisterFlagCompletionFunc("collectors", completeEnum(completionCollectors))
		}
		if c.Flag("profile-name") != nil {
			_ = c.RegisterFlagCompletionFunc("profile-name", completeOSCProfiles)
		}
		if c.Flag("snapshot-input") != nil {
			_ = c.RegisterFlagCompletionFunc("snapshot-input", completeJSONFile)
		}
		if c.Flag("snapshot-output") != nil {
			_ = c.RegisterFlagCompletionFunc("snapshot-output", completeJSONFile)
		}
		if c.Flag("compare") != nil {
			_ = c.RegisterFlagCompletionFunc("compare", completeJSONFile)
		}
		if strings.HasPrefix(c.Use, "plan ") && c.ValidArgsFunction == nil {
			c.ValidArgsFunction = completeJSONFile
		}
	})
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, sub := range c.Commands() {
		walk(sub, fn)
	}
}
