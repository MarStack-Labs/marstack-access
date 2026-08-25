package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/marstack-labs/marstack-access/internal/app"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
)

func newServerCmd() *cobra.Command {
	var (
		listen      string
		sshListen   string
		dataDir     string
		advertiseIP string
		devCAKey    string
		logLevel    string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the control plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			log := logging.New(logLevel, os.Stderr)

			a, err := app.New(ctx, app.Config{
				Listen:       listen,
				SSHListen:    sshListen,
				DataDir:      dataDir,
				AdvertiseIP:  advertiseIP,
				DevCAKeyPath: devCAKey,
			}, log)
			if err != nil {
				return err
			}
			defer a.Close()

			return a.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:7443", "address the control plane listens on")
	cmd.Flags().StringVar(&sshListen, "ssh-listen", "",
		"address the SSH data plane listens on, empty to leave it off")
	cmd.Flags().StringVar(&dataDir, "data-dir", "./data", "directory holding the control plane database")
	cmd.Flags().StringVar(&advertiseIP, "advertise-ip", "",
		"address targets see this gateway as, pinned into each session certificate")
	cmd.Flags().StringVar(&devCAKey, "dev-ca-key", "",
		"path to a signing key held locally, a development mode, see docs/SECURITY.md")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	return cmd
}
