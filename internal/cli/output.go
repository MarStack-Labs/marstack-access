package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const (
	outputTable = "table"
	outputJSON  = "json"
)

type table struct {
	headers []string
	rows    [][]string
}

func render(w io.Writer, format string, payload any, t table) error {
	switch format {
	case outputJSON:
		return renderJSON(w, payload)
	case outputTable:
		return renderTable(w, t)
	default:
		return fmt.Errorf("unknown output format %q: want %s or %s", format, outputTable, outputJSON)
	}
}

func renderJSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func renderTable(w io.Writer, t table) error {
	if len(t.rows) == 0 {
		_, err := fmt.Fprintln(w, "no results")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 8, 3, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(t.headers, "\t")); err != nil {
		return err
	}
	for _, row := range t.rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}
