package cmd

import (
	"github.com/spf13/cobra"
)

func rulesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "rules",
		Short: "Gestion des règles (liste, tests)",
	}
	c.AddCommand(rulesListCmd())
	c.AddCommand(rulesTestCmd())
	return c
}
