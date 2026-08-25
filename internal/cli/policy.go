package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type policyView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SubjectKind string   `json:"subject_kind"`
	SubjectID   string   `json:"subject_id"`
	TargetID    string   `json:"target_id"`
	Principals  []string `json:"principals"`
	CreatedAt   string   `json:"created_at"`
}

type policyListView struct {
	Policies []policyView `json:"policies"`
}

type decisionView struct {
	Allowed  bool   `json:"allowed"`
	PolicyID string `json:"policy_id,omitempty"`
	Reason   string `json:"reason"`
}

var policyHeaders = []string{"NAME", "ID", "SUBJECT", "TARGET", "PRINCIPALS", "CREATED"}

func policyRow(p policyView) []string {
	return []string{
		p.Name,
		p.ID,
		p.SubjectKind + ":" + p.SubjectID,
		p.TargetID,
		dashIfEmpty(strings.Join(p.Principals, ",")),
		p.CreatedAt,
	}
}

func newPolicyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "policy",
		Short:   "Manage who may reach which target as which principal",
		Aliases: []string{"policies"},
	}
	cmd.AddCommand(
		newPolicyCreateCmd(g),
		newPolicyListCmd(g),
		newPolicyGetCmd(g),
		newPolicyDeleteCmd(g),
		newPolicyEvaluateCmd(g),
	)
	return cmd
}

func newPolicyCreateCmd(g *globals) *cobra.Command {
	var (
		user string
		role string
		req  struct {
			Name        string   `json:"name"`
			SubjectKind string   `json:"subject_kind"`
			SubjectID   string   `json:"subject_id"`
			TargetID    string   `json:"target_id"`
			Principals  []string `json:"principals"`
		}
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Grant a user or a role access to one target",
		Long: "Grant access. Exactly one of --user or --role names the subject. A role is matched\n" +
			"exactly, so granting the operator role does not also grant admins.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case user != "" && role != "":
				return errBothSubjects
			case user != "":
				req.SubjectKind, req.SubjectID = "user", user
			case role != "":
				req.SubjectKind, req.SubjectID = "role", role
			default:
				return errNoSubject
			}

			var created policyView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/policies", req, &created,
			); err != nil {
				return err
			}
			return renderPolicy(cmd, g, created)
		},
	}

	cmd.Flags().StringVar(&req.Name, "name", "", "policy name, unique within the platform")
	cmd.Flags().StringVar(&user, "user", "", "user id this policy grants to")
	cmd.Flags().StringVar(&role, "role", "", "role this policy grants to: viewer, operator, admin")
	cmd.Flags().StringVar(&req.TargetID, "target", "", "target id the policy applies to")
	cmd.Flags().StringSliceVar(&req.Principals, "principal", nil,
		"account the subject may land as, repeatable")

	must(cmd.MarkFlagRequired("name"))
	must(cmd.MarkFlagRequired("target"))
	must(cmd.MarkFlagRequired("principal"))

	return cmd
}

func newPolicyListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list policyListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/policies", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Policies))
			for _, p := range list.Policies {
				rows = append(rows, policyRow(p))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: policyHeaders, rows: rows})
		},
	}
}

func newPolicyGetCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var p policyView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/policies/"+args[0], nil, &p,
			); err != nil {
				return err
			}
			return renderPolicy(cmd, g, p)
		},
	}
}

func newPolicyDeleteCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Revoke a policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(g).do(
				cmd.Context(), "DELETE", "/v1/policies/"+args[0], nil, nil,
			); err != nil {
				return err
			}
			cmd.Printf("deleted %s\n", args[0])
			return nil
		},
	}
}

func newPolicyEvaluateCmd(g *globals) *cobra.Command {
	var req struct {
		UserID    string `json:"user_id"`
		Role      string `json:"role,omitempty"`
		TargetID  string `json:"target_id"`
		Principal string `json:"principal"`
	}

	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Ask whether a request would be allowed, without opening a session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var decision decisionView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/policies/evaluate", req, &decision,
			); err != nil {
				return err
			}

			if g.output == outputJSON {
				return renderJSON(cmd.OutOrStdout(), decision)
			}

			cmd.Printf("allowed: %s\nreason:  %s\n",
				strconv.FormatBool(decision.Allowed), decision.Reason)
			return nil
		},
	}

	cmd.Flags().StringVar(&req.UserID, "user", "", "user id making the request")
	cmd.Flags().StringVar(&req.Role, "role", "", "role the user holds")
	cmd.Flags().StringVar(&req.TargetID, "target", "", "target id being reached")
	cmd.Flags().StringVar(&req.Principal, "principal", "", "account the session would land as")

	must(cmd.MarkFlagRequired("user"))
	must(cmd.MarkFlagRequired("target"))
	must(cmd.MarkFlagRequired("principal"))

	return cmd
}

func renderPolicy(cmd *cobra.Command, g *globals, p policyView) error {
	return render(cmd.OutOrStdout(), g.output, p, table{
		headers: policyHeaders,
		rows:    [][]string{policyRow(p)},
	})
}
