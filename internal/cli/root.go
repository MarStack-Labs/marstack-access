package cli

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "marac",
		Short: "MarStack Access control plane, data plane, and client",
		Long: "MarStack Access is an identity-aware access platform for Linux infrastructure.\n" +
			"Sessions authenticate with certificates minted per session; no target credential is stored.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newVersionCmd(),
		newServerCmd(),
	)
	return root
}

func Execute() error {
	return newRootCmd().Execute()
}
