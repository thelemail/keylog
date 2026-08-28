package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	buildCommit = "unknown"
	buildRef    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build commit and ref",
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintf(c.OutOrStdout(), "commit: %s\nref:    %s\n", buildCommit, buildRef)
		},
	}
}
