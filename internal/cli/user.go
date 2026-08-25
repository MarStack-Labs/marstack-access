package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type userView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
}

type userListView struct {
	Users []userView `json:"users"`
}

var userHeaders = []string{"NAME", "ID", "ROLE", "DISABLED", "CREATED"}

func userRow(u userView) []string {
	return []string{u.Name, u.ID, u.Role, strconv.FormatBool(u.Disabled), u.CreatedAt}
}

func newUserCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user",
		Short:   "Manage platform users",
		Aliases: []string{"users"},
	}
	cmd.AddCommand(
		newUserCreateCmd(g),
		newUserListCmd(g),
		newUserGetCmd(g),
		newUserDeleteCmd(g),
	)
	return cmd
}

func newUserCreateCmd(g *globals) *cobra.Command {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var created userView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/users", req, &created,
			); err != nil {
				return err
			}
			return renderUser(cmd, g, created)
		},
	}

	cmd.Flags().StringVar(&req.Name, "name", "", "user name, unique within the platform")
	cmd.Flags().StringVar(&req.Role, "role", "", "role: viewer, operator, admin")

	must(cmd.MarkFlagRequired("name"))
	must(cmd.MarkFlagRequired("role"))

	return cmd
}

func newUserListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list userListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/users", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Users))
			for _, u := range list.Users {
				rows = append(rows, userRow(u))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: userHeaders, rows: rows})
		},
	}
}

func newUserGetCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var u userView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/users/"+args[0], nil, &u,
			); err != nil {
				return err
			}
			return renderUser(cmd, g, u)
		},
	}
}

func newUserDeleteCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a user and revoke every token it holds",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(g).do(
				cmd.Context(), "DELETE", "/v1/users/"+args[0], nil, nil,
			); err != nil {
				return err
			}
			cmd.Printf("deleted %s\n", args[0])
			return nil
		},
	}
}

func renderUser(cmd *cobra.Command, g *globals, u userView) error {
	return render(cmd.OutOrStdout(), g.output, u, table{
		headers: userHeaders,
		rows:    [][]string{userRow(u)},
	})
}

func dashIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
