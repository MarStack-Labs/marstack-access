package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type targetView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	Principals []string `json:"principals"`
	CreatedAt  string   `json:"created_at"`
}

type targetListView struct {
	Targets []targetView `json:"targets"`
}

var targetHeaders = []string{"NAME", "ID", "ADDRESS", "PORT", "PRINCIPALS", "CREATED"}

func targetRow(t targetView) []string {
	principals := strings.Join(t.Principals, ",")
	if principals == "" {
		principals = "-"
	}

	return []string{
		t.Name,
		t.ID,
		t.Address,
		strconv.Itoa(t.Port),
		principals,
		t.CreatedAt,
	}
}

func newTargetCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "target",
		Short:   "Manage the target inventory",
		Aliases: []string{"targets"},
	}
	cmd.AddCommand(
		newTargetRegisterCmd(g),
		newTargetListCmd(g),
		newTargetGetCmd(g),
		newTargetDeleteCmd(g),
	)
	return cmd
}

func newTargetRegisterCmd(g *globals) *cobra.Command {
	var req struct {
		Name       string   `json:"name"`
		Address    string   `json:"address"`
		Port       int      `json:"port,omitempty"`
		Principals []string `json:"principals"`
	}

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a target the platform may reach",
		Long: "Register a target. The principals given here are the accounts a session may land as,\n" +
			"and they must match what the target's sshd is configured to accept.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var created targetView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/targets", req, &created,
			); err != nil {
				return err
			}
			return renderTarget(cmd, g, created)
		},
	}

	cmd.Flags().StringVar(&req.Name, "name", "", "target name, unique within the platform")
	cmd.Flags().StringVar(&req.Address, "address", "", "IP address or hostname of the target")
	cmd.Flags().IntVar(&req.Port, "port", 0, "SSH port, defaults to the platform default")
	cmd.Flags().StringSliceVar(&req.Principals, "principal", nil,
		"account a session may land as, repeatable")

	must(cmd.MarkFlagRequired("name"))
	must(cmd.MarkFlagRequired("address"))
	must(cmd.MarkFlagRequired("principal"))

	return cmd
}

func newTargetListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered targets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list targetListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/targets", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Targets))
			for _, t := range list.Targets {
				rows = append(rows, targetRow(t))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: targetHeaders, rows: rows})
		},
	}
}

func newTargetGetCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var t targetView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/targets/"+args[0], nil, &t,
			); err != nil {
				return err
			}
			return renderTarget(cmd, g, t)
		},
	}
}

func newTargetDeleteCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Remove a target from the inventory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClient(g).do(
				cmd.Context(), "DELETE", "/v1/targets/"+args[0], nil, nil,
			); err != nil {
				return err
			}
			cmd.Printf("deleted %s\n", args[0])
			return nil
		},
	}
}

func renderTarget(cmd *cobra.Command, g *globals, t targetView) error {
	return render(cmd.OutOrStdout(), g.output, t, table{
		headers: targetHeaders,
		rows:    [][]string{targetRow(t)},
	})
}
