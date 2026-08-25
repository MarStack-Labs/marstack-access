package cli

import (
	"github.com/spf13/cobra"
)

type tokenView struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Selector  string `json:"selector"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type tokenListView struct {
	Tokens []tokenView `json:"tokens"`
}

type issuedTokenView struct {
	tokenView
	Secret string `json:"secret"`
}

var tokenHeaders = []string{"ID", "USER", "SELECTOR", "CREATED", "EXPIRES"}

func tokenRow(t tokenView) []string {
	return []string{t.ID, t.UserID, t.Selector, t.CreatedAt, dashIfEmpty(t.ExpiresAt)}
}

func newTokenCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token",
		Short:   "Manage API tokens",
		Aliases: []string{"tokens"},
	}
	cmd.AddCommand(
		newTokenIssueCmd(g),
		newTokenListCmd(g),
		newTokenRevokeCmd(g),
	)
	return cmd
}

func newTokenIssueCmd(g *globals) *cobra.Command {
	var (
		user string
		req  struct {
			TTL string `json:"ttl,omitempty"`
		}
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a token for a user and print it once",
		Long: "Issue a token. The secret is printed once and is not recoverable afterwards,\n" +
			"because nothing stores it. Losing it means issuing another.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var issued issuedTokenView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/users/"+user+"/tokens", req, &issued,
			); err != nil {
				return err
			}

			if g.output == outputJSON {
				return renderJSON(cmd.OutOrStdout(), issued)
			}

			cmd.Println(issued.Secret)
			cmd.Printf("\nid %s for user %s. This secret is not shown again.\n", issued.ID, issued.UserID)
			return nil
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "user id the token authenticates as")
	cmd.Flags().StringVar(&req.TTL, "ttl", "", "lifetime such as 24h or 30m, empty for no expiry")

	must(cmd.MarkFlagRequired("user"))

	return cmd
}

func newTokenListCmd(g *globals) *cobra.Command {
	var user string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a user's tokens without their secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list tokenListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/users/"+user+"/tokens", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Tokens))
			for _, t := range list.Tokens {
				rows = append(rows, tokenRow(t))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: tokenHeaders, rows: rows})
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "user id whose tokens to list")
	must(cmd.MarkFlagRequired("user"))

	return cmd
}

func newTokenRevokeCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token immediately",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(g).do(
				cmd.Context(), "DELETE", "/v1/tokens/"+args[0], nil, nil,
			); err != nil {
				return err
			}
			cmd.Printf("revoked %s\n", args[0])
			return nil
		},
	}
}
