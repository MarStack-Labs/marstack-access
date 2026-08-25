package cli

import (
	"os"

	"github.com/spf13/cobra"
)

type globals struct {
	endpoint string
	output   string
}

func resolveDefaultEndpoint() string {
	if v := os.Getenv(endpointEnvVar); v != "" {
		return v
	}
	return defaultEndpoint
}

func newRootCmd() *cobra.Command {
	g := &globals{}

	root := &cobra.Command{
		Use:   "marac",
		Short: "MarStack Access control plane, data plane, and client",
		Long: "MarStack Access is an identity-aware access platform for Linux infrastructure.\n" +
			"Sessions authenticate with certificates minted per session; no target credential is stored.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&g.endpoint, "endpoint", resolveDefaultEndpoint(),
		"control plane endpoint, overrides "+endpointEnvVar)
	root.PersistentFlags().StringVarP(&g.output, "output", "o", outputTable,
		"output format: table, json")

	root.AddCommand(
		newVersionCmd(),
		newServerCmd(),
		newTargetCmd(g),
	)
	return root
}

func Execute() error {
	return newRootCmd().Execute()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
