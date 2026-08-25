package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the development signing authority",
		Long: "Manage a signing authority held in a local file.\n\n" +
			"This is a development mode. A production deployment keeps the signing key in\n" +
			"marstack-secrets, so no process that terminates user traffic ever holds it.",
	}
	cmd.AddCommand(newCAInitCmd(), newCAShowCmd())
	return cmd
}

func newCAInitCmd() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a signing key and print what to install on a target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := certs.Create(path)
			if err != nil {
				return err
			}

			cmd.Printf("created %s\n", path)
			printTargetSetup(cmd, pub)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "where to write the signing key")
	must(cmd.MarkFlagRequired("path"))

	return cmd
}

func newCAShowCmd() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the signing authority's public key and fingerprint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			signer, err := certs.Load(path)
			if err != nil {
				return err
			}
			printTargetSetup(cmd, signer.PublicKey())
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to the signing key")
	must(cmd.MarkFlagRequired("path"))

	return cmd
}

func printTargetSetup(cmd *cobra.Command, pub ssh.PublicKey) {
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	cmd.Printf("fingerprint %s\n\n", ssh.FingerprintSHA256(pub))
	cmd.Println("Install this on every target, then reload sshd:")
	cmd.Println()
	cmd.Printf("  echo %q | sudo tee /etc/ssh/marstack_ca.pub\n", authorized)
	cmd.Println("  # in /etc/ssh/sshd_config")
	cmd.Println("  TrustedUserCAKeys /etc/ssh/marstack_ca.pub")
	cmd.Println("  AuthorizedPrincipalsFile /etc/ssh/principals/%u")
	cmd.Println()
	cmd.Println("Nothing else is installed on the target, and no daemon runs there.")
}
