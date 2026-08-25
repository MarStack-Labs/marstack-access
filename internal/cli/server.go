package cli

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marstack-labs/marstack-access/internal/app"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/kernel/objstore"
)

const (
	s3AccessKeyEnv = "MARAC_S3_ACCESS_KEY"
	s3SecretKeyEnv = "MARAC_S3_SECRET_KEY"
)

func newServerCmd() *cobra.Command {
	var (
		listen      string
		sshListen   string
		dataDir     string
		advertiseIP string
		devCAKey    string
		lokiURL     string
		logLevel    string

		recEndpoint string
		recBucket   string
		recRegion   string
		recRetain   time.Duration
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
				LokiURL:      lokiURL,
				Recordings: objstore.Config{
					Endpoint:  recEndpoint,
					Bucket:    recBucket,
					Region:    recRegion,
					AccessKey: os.Getenv(s3AccessKeyEnv),
					SecretKey: os.Getenv(s3SecretKeyEnv),
					RetainFor: recRetain,
				},
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
	cmd.Flags().StringVar(&lokiURL, "audit-loki-url", "",
		"base URL of a Loki the audit trail ships to, empty to keep the trail on this host only")
	cmd.Flags().StringVar(&recEndpoint, "recording-endpoint", "",
		"MinIO or S3 endpoint recordings are stored in, empty to keep them on this host only")
	cmd.Flags().StringVar(&recBucket, "recording-bucket", "",
		"bucket recordings are written to, created with object lock enabled")
	cmd.Flags().StringVar(&recRegion, "recording-region", "us-east-1", "region used when signing")
	cmd.Flags().DurationVar(&recRetain, "recording-retain-for", 90*24*time.Hour,
		"how long the object lock holds a recording, zero to upload without a lock")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	return cmd
}
