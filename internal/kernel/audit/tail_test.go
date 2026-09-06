package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTrail(t *testing.T, count int) string {
	t.Helper()

	dir := t.TempDir()
	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	events := make([]Event, count)
	for i := range events {
		events[i] = Event{
			At:      time.Unix(int64(1700000000+i), 0).UTC(),
			Action:  fmt.Sprintf("event.%d", i),
			Outcome: OutcomeAllowed,
		}
	}
	if err := sink.Append(context.Background(), events); err != nil {
		t.Fatalf("append: %v", err)
	}
	return sink.Path()
}

func TestTailReturnsTheNewestEventFirst(t *testing.T) {
	got, err := Tail(writeTrail(t, 10), 3)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	want := []string{"event.9", "event.8", "event.7"}
	for i, action := range want {
		if got[i].Action != action {
			t.Errorf("event %d = %q, want %q: a reader opens this to see what just happened",
				i, got[i].Action, action)
		}
	}
}

func TestTailIsCappedNoMatterWhatIsAskedFor(t *testing.T) {
	got, err := Tail(writeTrail(t, MaxTail+50), MaxTail*10)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}

	if len(got) != MaxTail {
		t.Fatalf("got %d events, want %d: an unbounded read of this file is a denial of service "+
			"that any authenticated caller can trigger", len(got), MaxTail)
	}
}

func TestTailOfATrailThatDoesNotExistIsEmpty(t *testing.T) {
	got, err := Tail(filepath.Join(t.TempDir(), "audit.jsonl"), 10)

	if err != nil {
		t.Fatalf("tail: %v, want no error: a gateway that has recorded nothing is not broken", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d events from a file that does not exist", len(got))
	}
}

func TestTailReadsOnlyTheEndOfALargeTrail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	var b strings.Builder
	filler := strings.Repeat("x", 1024)
	for b.Len() < tailWindow*2 {
		fmt.Fprintf(&b, `{"at":"2026-01-01T00:00:00Z","action":"old","fields":{"pad":%q}}`+"\n", filler)
	}
	b.WriteString(`{"at":"2026-01-01T00:00:01Z","action":"newest"}` + "\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Tail(path, 5)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(got) == 0 || got[0].Action != "newest" {
		t.Fatalf("newest event = %v, want the last line of the file", got)
	}
}

const fixedLine = 4096

func lineOfFixedWidth(i int) string {
	head := fmt.Sprintf(`{"action":"e%06d","fields":{"pad":"`, i)
	tail := `"}}` + "\n"
	return head + strings.Repeat("x", fixedLine-len(head)-len(tail)) + tail
}

func TestAnEventIsNotLostWhenTheWindowOpensExactlyOnALineBoundary(t *testing.T) {
	if tailWindow%fixedLine != 0 {
		t.Fatalf("this test needs the window to be a whole number of lines")
	}
	inWindow := tailWindow / fixedLine
	extra := 3

	var b strings.Builder
	for i := range inWindow + extra {
		b.WriteString(lineOfFixedWidth(i))
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Tail(path, MaxTail)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}

	if len(got) != inWindow {
		t.Fatalf("got %d events, want %d", len(got), inWindow)
	}
	if oldest := got[len(got)-1].Action; oldest != fmt.Sprintf("e%06d", extra) {
		t.Fatalf("oldest event in the window = %q, want %q: the seek landed on a line boundary, "+
			"so the line it landed on is whole and discarding it silently loses a record",
			oldest, fmt.Sprintf("e%06d", extra))
	}
}

func TestAHalfLineAtTheWindowEdgeIsSkipped(t *testing.T) {
	var b strings.Builder
	for i := range tailWindow/fixedLine + 3 {
		b.WriteString(lineOfFixedWidth(i))
	}
	content := "prefix that shifts every boundary off a line start\n" + b.String()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Tail(path, MaxTail)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("nothing was read")
	}
	for _, e := range got {
		if !strings.HasPrefix(e.Action, "e0") {
			t.Fatalf("a fragment of a line was parsed into %+v rather than skipped", e)
		}
	}
}

func TestALineThatIsNotAnEventIsSkippedRatherThanFailingTheRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	content := `{"at":"2026-01-01T00:00:00Z","action":"first"}` + "\n" +
		"{not json at all" + "\n" +
		`{"at":"2026-01-01T00:00:02Z","action":"third"}` + "\n" +
		`{"at":"2026-01-01T00:00:03Z","action":"fourth"`

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Tail(path, 10)
	if err != nil {
		t.Fatalf("tail: %v, want no error: one damaged line must not hide every good one", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2 (first and third)", len(got))
	}
	if got[0].Action != "third" || got[1].Action != "first" {
		t.Fatalf("got %q then %q, want third then first", got[0].Action, got[1].Action)
	}
}

func TestTailKeepsTheFieldsAReaderCameFor(t *testing.T) {
	dir := t.TempDir()
	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	defer sink.Close()

	err = sink.Append(context.Background(), []Event{{
		At:        time.Unix(1700000000, 0).UTC(),
		Action:    "request.approved",
		Outcome:   OutcomeAllowed,
		ActorID:   "usr-1",
		ActorName: "rina",
		Object:    "req-1",
		Reason:    "",
		Fields:    map[string]string{"target": "tgt-1"},
	}})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := Tail(sink.Path(), 1)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}

	e := got[0]
	if e.ActorName != "rina" || e.Object != "req-1" || e.Fields["target"] != "tgt-1" {
		t.Fatalf("event lost detail in the round trip: %+v", e)
	}
}

func TestTailOfNothingIsNotAnError(t *testing.T) {
	got, err := Tail(writeTrail(t, 0), 10)

	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d events from an empty trail", len(got))
	}
}

func TestAskingForNothingReturnsNothing(t *testing.T) {
	got, err := Tail(writeTrail(t, 10), 0)

	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d events for a limit of zero", len(got))
	}
}
