package cli

import (
	"strconv"

	"github.com/spf13/cobra"
)

type sessionView struct {
	ID            string `json:"id"`
	Active        bool   `json:"active"`
	UserID        string `json:"user_id"`
	UserName      string `json:"user_name"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	Principal     string `json:"principal"`
	CredentialID  string `json:"credential_id"`
	RemoteAddr    string `json:"remote_addr"`
	Recording     string `json:"recording"`
	StartedAt     string `json:"started_at"`
	EndedAt       string `json:"ended_at,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	RecordedBytes int64  `json:"recorded_bytes"`
}

type sessionListView struct {
	Sessions []sessionView `json:"sessions"`
}

type killView struct {
	Killed  bool        `json:"killed"`
	Session sessionView `json:"session"`
	Note    string      `json:"note,omitempty"`
}

var sessionHeaders = []string{"ID", "STATE", "USER", "TARGET", "PRINCIPAL", "STARTED", "BYTES"}

func sessionRow(s sessionView) []string {
	state := "closed"
	if s.Active {
		state = "active"
	}

	return []string{
		s.ID,
		state,
		s.UserName,
		s.TargetName,
		s.Principal,
		s.StartedAt,
		strconv.FormatInt(s.RecordedBytes, 10),
	}
}

func newSessionCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "session",
		Short:   "Inspect and close sessions",
		Aliases: []string{"sessions"},
	}
	cmd.AddCommand(
		newSessionListCmd(g),
		newSessionGetCmd(g),
		newSessionKillCmd(g),
	)
	return cmd
}

func newSessionListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List sessions, own only unless admin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var list sessionListView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/sessions", nil, &list,
			); err != nil {
				return err
			}

			rows := make([][]string, 0, len(list.Sessions))
			for _, s := range list.Sessions {
				rows = append(rows, sessionRow(s))
			}
			return render(cmd.OutOrStdout(), g.output, list, table{headers: sessionHeaders, rows: rows})
		},
	}
}

func newSessionGetCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one session, including where its recording is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var s sessionView
			if err := newClient(g).do(
				cmd.Context(), "GET", "/v1/sessions/"+args[0], nil, &s,
			); err != nil {
				return err
			}

			if g.output == outputJSON {
				return renderJSON(cmd.OutOrStdout(), s)
			}

			if err := render(cmd.OutOrStdout(), g.output, s, table{
				headers: sessionHeaders,
				rows:    [][]string{sessionRow(s)},
			}); err != nil {
				return err
			}

			cmd.Printf("\nrecording %s\n", s.Recording)
			if s.Reason != "" {
				cmd.Printf("reason    %s\n", s.Reason)
			}
			return nil
		},
	}
}

func newSessionKillCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "kill <id>",
		Short: "Close a live session now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var result killView
			if err := newClient(g).do(
				cmd.Context(), "POST", "/v1/sessions/"+args[0]+"/kill", nil, &result,
			); err != nil {
				return err
			}

			if g.output == outputJSON {
				return renderJSON(cmd.OutOrStdout(), result)
			}

			if result.Killed {
				cmd.Printf("closed %s\n", args[0])
			} else {
				cmd.Printf("not closed: %s\n", result.Note)
			}
			return nil
		},
	}
}
