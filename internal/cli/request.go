package cli

import (
	"strconv"

	"github.com/spf13/cobra"
)

type requestView struct {
	ID             string `json:"id"`
	RequesterID    string `json:"requester_id"`
	TargetID       string `json:"target_id"`
	Principal      string `json:"principal"`
	Reason         string `json:"reason"`
	State          string `json:"state"`
	GrantTTL       string `json:"grant_ttl"`
	CreatedAt      string `json:"created_at"`
	RequestExpires string `json:"request_expires_at"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	GrantExpires   string `json:"grant_expires_at,omitempty"`
}

type requestListView struct {
	Requests []requestView `json:"requests"`
}

type grantView struct {
	Active    bool   `json:"active"`
	RequestID string `json:"request_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

var requestHeaders = []string{"ID", "STATE", "REQUESTER", "TARGET", "PRINCIPAL", "GRANT EXPIRES", "REASON"}

func requestRow(r requestView) []string {
	reason := r.Reason
	if len(reason) > 40 {
		reason = reason[:37] + "..."
	}

	return []string{
		r.ID,
		r.State,
		r.RequesterID,
		r.TargetID,
		r.Principal,
		dashIfEmpty(r.GrantExpires),
		dashIfEmpty(reason),
	}
}

func newRequestCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "request",
		Short:   "Raise and decide just-in-time access requests",
		Aliases: []string{"requests"},
	}
	cmd.AddCommand(
		newRequestCreateCmd(g),
		newRequestListCmd(g),
		newRequestGetCmd(g),
		newRequestCancelCmd(g),
		newRequestApproveCmd(g),
		newRequestDenyCmd(g),
		newRequestGrantCmd(g),
	)
	return cmd
}

func newRequestCreateCmd(g *globals) *cobra.Command {
	var req struct {
		TargetID  string `json:"target_id"`
		Principal string `json:"principal"`
		Reason    string `json:"reason"`
		TTL       string `json:"ttl,omitempty"`
	}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Ask for time-boxed access to one target",
		Long: "Raise an access request. The requester is taken from the token, never from a flag,\n" +
			"and the request is refused up front if no policy could ever permit it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var created requestView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/access-requests", req, &created,
			); err != nil {
				return err
			}
			return renderRequest(cmd, g, created)
		},
	}

	cmd.Flags().StringVar(&req.TargetID, "target", "", "target id being requested")
	cmd.Flags().StringVar(&req.Principal, "principal", "", "account the session would land as")
	cmd.Flags().StringVar(&req.Reason, "reason", "", "why access is needed, recorded on the request")
	cmd.Flags().StringVar(&req.TTL, "ttl", "", "how long the grant should last, such as 2h")

	must(cmd.MarkFlagRequired("target"))
	must(cmd.MarkFlagRequired("principal"))
	must(cmd.MarkFlagRequired("reason"))

	return cmd
}

func newRequestListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List access requests, own only unless admin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list requestListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/access-requests", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Requests))
			for _, r := range list.Requests {
				rows = append(rows, requestRow(r))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: requestHeaders, rows: rows})
		},
	}
}

func newRequestGetCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var r requestView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/access-requests/"+args[0], nil, &r,
			); err != nil {
				return err
			}
			return renderRequest(cmd, g, r)
		},
	}
}

func newRequestApproveCmd(g *globals) *cobra.Command {
	return newRequestDecisionCmd(g, "approve", "Approve a request and open its grant")
}

func newRequestDenyCmd(g *globals) *cobra.Command {
	return newRequestDecisionCmd(g, "deny", "Refuse a request")
}

func newRequestCancelCmd(g *globals) *cobra.Command {
	return newRequestDecisionCmd(g, "cancel", "Withdraw a request you raised")
}

func newRequestDecisionCmd(g *globals, verb, short string) *cobra.Command {
	return &cobra.Command{
		Use:   verb + " <id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var r requestView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/access-requests/"+args[0]+"/"+verb, nil, &r,
			); err != nil {
				return err
			}
			return renderRequest(cmd, g, r)
		},
	}
}

func newRequestGrantCmd(g *globals) *cobra.Command {
	var req struct {
		UserID    string `json:"user_id"`
		TargetID  string `json:"target_id"`
		Principal string `json:"principal"`
	}

	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Ask whether a live grant exists right now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var g2 grantView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/access-requests/grant", req, &g2,
			); err != nil {
				return err
			}

			if g.output == outputJSON {
				return renderJSON(cmd.OutOrStdout(), g2)
			}

			cmd.Printf("active:  %s\n", strconv.FormatBool(g2.Active))
			if g2.Active {
				cmd.Printf("request: %s\nexpires: %s\nreason:  %s\n",
					g2.RequestID, g2.ExpiresAt, g2.Reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&req.UserID, "user", "", "user id to check")
	cmd.Flags().StringVar(&req.TargetID, "target", "", "target id to check")
	cmd.Flags().StringVar(&req.Principal, "principal", "", "principal to check")

	must(cmd.MarkFlagRequired("user"))
	must(cmd.MarkFlagRequired("target"))
	must(cmd.MarkFlagRequired("principal"))

	return cmd
}

func renderRequest(cmd *cobra.Command, g *globals, r requestView) error {
	return render(cmd.OutOrStdout(), g.output, r, table{
		headers: requestHeaders,
		rows:    [][]string{requestRow(r)},
	})
}
