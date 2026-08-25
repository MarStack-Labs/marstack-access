package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memorySink struct {
	mu     sync.Mutex
	events []Event
	fail   error
}

func (s *memorySink) Append(_ context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fail != nil {
		return s.fail
	}
	s.events = append(s.events, events...)
	return nil
}

func (s *memorySink) all() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]Event{}, s.events...)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readTrail(t *testing.T, path string) []Event {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}

	events := []Event{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("trail line is not JSON: %v (%s)", err, line)
		}
		events = append(events, e)
	}
	return events
}

func TestAnEventIsWrittenToTheDurableTrail(t *testing.T) {
	dir := t.TempDir()
	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	defer sink.Close()

	trail := New(discardLogger(), sink, nil)
	defer trail.Close()

	if err := trail.Record(context.Background(), Event{
		Action:    "session.opened",
		ActorID:   "usr-1",
		ActorName: "alice",
		Object:    "ses-1",
		Fields:    map[string]string{"target": "db-1"},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	events := readTrail(t, sink.Path())
	if len(events) != 1 {
		t.Fatalf("%d events written, want 1", len(events))
	}
	if events[0].Action != "session.opened" || events[0].ActorName != "alice" {
		t.Fatalf("event = %+v", events[0])
	}
	if events[0].Outcome != OutcomeAllowed {
		t.Errorf("outcome = %q, want it defaulted to %q rather than left blank", events[0].Outcome, OutcomeAllowed)
	}
	if events[0].At.IsZero() {
		t.Error("the event carries no timestamp")
	}
}

func TestTheTrailIsAppendedNeverTruncated(t *testing.T) {
	dir := t.TempDir()

	for round := range 3 {
		sink, err := OpenFileSink(dir)
		if err != nil {
			t.Fatalf("round %d open: %v", round, err)
		}
		trail := New(discardLogger(), sink, nil)
		if err := trail.Record(context.Background(), Event{Action: "round"}); err != nil {
			t.Fatalf("round %d record: %v", round, err)
		}
		trail.Close()
		sink.Close()
	}

	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sink.Close()

	events := readTrail(t, sink.Path())
	if len(events) != 3 {
		t.Fatalf("%d events after three restarts, want 3: reopening the trail must not truncate what is already there", len(events))
	}
}

func TestADurableWriteFailureIsReportedToTheCaller(t *testing.T) {
	broken := &memorySink{fail: errors.New("disk full")}
	trail := New(discardLogger(), broken, nil)
	defer trail.Close()

	err := trail.Record(context.Background(), Event{Action: "session.opened"})
	if err == nil {
		t.Fatal("Record swallowed a durable write failure. The caller has to be able to refuse a session it cannot record")
	}
}

func TestTheTrailFileIsNotWorldReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sink.Close()

	info, err := os.Stat(sink.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != trailPerm {
		t.Fatalf("trail mode = %#o, want %#o: the file is what carries the events", perm, trailPerm)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != trailDirPerm {
		t.Fatalf("audit dir mode = %#o, want %#o when we create it. MkdirAll leaves an existing directory alone, so this only holds for a directory we made",
			perm, trailDirPerm)
	}
}

func TestEventsAreShippedAsWellAsWritten(t *testing.T) {
	durable := &memorySink{}
	shipped := &memorySink{}
	trail := New(discardLogger(), durable, shipped)

	for i := range 5 {
		if err := trail.Record(context.Background(), Event{
			Action: "session.opened",
			Object: "ses-" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	if err := trail.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := len(durable.all()); got != 5 {
		t.Fatalf("%d events written durably, want 5", got)
	}
	if got := len(shipped.all()); got != 5 {
		t.Fatalf("%d events shipped, want 5: Close has to drain the queue or a restart loses whatever was in flight", got)
	}
}

func TestAShippingFailureDoesNotFailTheCaller(t *testing.T) {
	durable := &memorySink{}
	shipped := &memorySink{fail: errors.New("loki is down")}
	trail := New(discardLogger(), durable, shipped)

	if err := trail.Record(context.Background(), Event{Action: "session.opened"}); err != nil {
		t.Fatalf("Record failed because shipping failed: %v. A session must not depend on a log aggregator being up, because the durable trail already has the event", err)
	}

	if err := trail.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := len(durable.all()); got != 1 {
		t.Fatalf("%d events written durably, want 1", got)
	}
}

func TestAFullQueueDropsShipmentAndCountsIt(t *testing.T) {
	durable := &memorySink{}
	blocked := make(chan struct{})
	slow := &blockingSink{release: blocked}

	trail := New(discardLogger(), durable, slow)

	flood := 2*queueDepth + 2*flushBatch
	for range flood {
		if err := trail.Record(context.Background(), Event{Action: "flood"}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	if trail.Dropped() == 0 {
		t.Fatal("a full shipment queue dropped nothing, so Record must have blocked. Blocking on a slow aggregator would stall every session")
	}
	if got := len(durable.all()); got != flood {
		t.Fatalf("%d events written durably, want all %d: dropping a shipment must never drop the durable write",
			got, flood)
	}

	close(blocked)
	trail.Close()
}

type blockingSink struct {
	release chan struct{}
}

func (s *blockingSink) Append(context.Context, []Event) error {
	<-s.release
	return nil
}

func TestLokiReceivesOneStreamPerActionAndOutcome(t *testing.T) {
	var received lokiPush

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pushPath {
			t.Errorf("path = %q, want %q", r.URL.Path, pushPath)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sink := NewLokiSink(server.URL, "marstack-access")
	at := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	if err := sink.Append(context.Background(), []Event{
		{At: at, Action: "session.opened", Outcome: OutcomeAllowed, Object: "ses-1", ActorID: "usr-1"},
		{At: at, Action: "session.opened", Outcome: OutcomeAllowed, Object: "ses-2", ActorID: "usr-2"},
		{At: at, Action: "session.refused", Outcome: OutcomeDenied, Object: "ses-3", ActorID: "usr-1"},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	if len(received.Streams) != 2 {
		t.Fatalf("%d streams, want 2: one per action and outcome pair", len(received.Streams))
	}

	for _, stream := range received.Streams {
		for label := range stream.Stream {
			switch label {
			case "job", "action", "outcome":
			default:
				t.Errorf("stream carries the label %q. Loki indexes labels, so an id in a label makes one stream per session and eventually takes the aggregator down",
					label)
			}
		}
		for _, value := range stream.Values {
			if !strings.Contains(value[1], "ses-") {
				t.Errorf("the line does not carry the object id: %s", value[1])
			}
		}
	}
}

func TestLokiRefusingThePushIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := io.WriteString(w, "entry out of order"); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer server.Close()

	err := NewLokiSink(server.URL, "").Append(context.Background(),
		[]Event{{At: time.Now(), Action: "session.opened"}})

	if err == nil {
		t.Fatal("a refused push was reported as success")
	}
	if !strings.Contains(err.Error(), "entry out of order") {
		t.Fatalf("error = %q, want it to carry what Loki said so the cause is diagnosable", err)
	}
}

func TestLokiPushIsEmptySafe(t *testing.T) {
	if err := NewLokiSink("http://127.0.0.1:1", "").Append(context.Background(), nil); err != nil {
		t.Fatalf("an empty batch tried to talk to the network: %v", err)
	}
}

func TestTheTrailPathIsUnderTheGivenDirectory(t *testing.T) {
	dir := t.TempDir()
	sink, err := OpenFileSink(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sink.Close()

	if want := filepath.Join(dir, trailName); sink.Path() != want {
		t.Fatalf("path = %q, want %q", sink.Path(), want)
	}
}
