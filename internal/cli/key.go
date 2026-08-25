package cli

import (
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const maxPipedKeyBytes = 1 << 16

type keyView struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
}

type keyListView struct {
	Keys []keyView `json:"keys"`
}

var keyHeaders = []string{"NAME", "ID", "USER", "TYPE", "FINGERPRINT", "CREATED"}

func keyRow(k keyView) []string {
	return []string{k.Name, k.ID, k.UserID, k.Type, k.Fingerprint, k.CreatedAt}
}

func newKeyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key",
		Short:   "Manage the SSH public keys an account may connect with",
		Aliases: []string{"keys"},
	}
	cmd.AddCommand(
		newKeyAddCmd(g),
		newKeyListCmd(g),
		newKeyRemoveCmd(g),
	)
	return cmd
}

func newKeyAddCmd(g *globals) *cobra.Command {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	var user string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register a public key for a user",
		Long: "Register a public key. Pass it with --public-key, or pipe it on stdin:\n\n" +
			"  marac key add --user usr-xxx --name laptop < ~/.ssh/id_ed25519.pub\n\n" +
			"A key may belong to only one account, so the platform can always say who acted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if req.PublicKey == "" {
				piped, err := readPipedKey(cmd)
				if err != nil {
					return err
				}
				req.PublicKey = piped
			}

			var created keyView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/users/"+user+"/keys", req, &created,
			); err != nil {
				return err
			}
			return renderKey(cmd, g, created)
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "user id the key belongs to")
	cmd.Flags().StringVar(&req.Name, "name", "", "label for the key, unique per user")
	cmd.Flags().StringVar(&req.PublicKey, "public-key", "",
		"the authorized_keys line, or omit it and pipe the key on stdin")

	must(cmd.MarkFlagRequired("user"))
	must(cmd.MarkFlagRequired("name"))

	return cmd
}

func readPipedKey(cmd *cobra.Command) (string, error) {
	if in, ok := cmd.InOrStdin().(*os.File); ok {
		info, err := in.Stat()
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeCharDevice != 0 {
			return "", errNoKeySource
		}
	}

	raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxPipedKeyBytes))
	if err != nil {
		return "", err
	}

	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", errNoKeySource
	}
	return key, nil
}

func newKeyListCmd(g *globals) *cobra.Command {
	var user string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a user's public keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list keyListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/users/"+user+"/keys", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Keys))
			for _, k := range list.Keys {
				rows = append(rows, keyRow(k))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: keyHeaders, rows: rows})
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "user id whose keys to list")
	must(cmd.MarkFlagRequired("user"))

	return cmd
}

func newKeyRemoveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove a public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(g).do(
				cmd.Context(), "DELETE", "/v1/keys/"+args[0], nil, nil,
			); err != nil {
				return err
			}
			cmd.Printf("removed %s\n", args[0])
			return nil
		},
	}
}

func renderKey(cmd *cobra.Command, g *globals, k keyView) error {
	return render(cmd.OutOrStdout(), g.output, k, table{
		headers: keyHeaders,
		rows:    [][]string{keyRow(k)},
	})
}
