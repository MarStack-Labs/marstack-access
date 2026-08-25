package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	OutcomeAllowed = "allowed"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"

	ActorSystem = "system"

	queueDepth  = 1024
	flushEvery  = 2 * time.Second
	flushBatch  = 64
	shipTimeout = 10 * time.Second
)

type Event struct {
	At        time.Time         `json:"at"`
	Action    string            `json:"action"`
	Outcome   string            `json:"outcome"`
	ActorID   string            `json:"actor_id,omitempty"`
	ActorName string            `json:"actor_name,omitempty"`
	Object    string            `json:"object,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type Sink interface {
	Append(ctx context.Context, events []Event) error
}

type Trail interface {
	Record(ctx context.Context, e Event) error
}

type discard struct{}

func (discard) Record(context.Context, Event) error {
	return nil
}

func Discard() Trail {
	return discard{}
}

type Recorder struct {
	durable Sink
	shipped Sink
	log     *slog.Logger
	now     func() time.Time

	queue   chan Event
	done    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	dropped int64
}

func New(log *slog.Logger, durable, shipped Sink) *Recorder {
	r := &Recorder{
		durable: durable,
		shipped: shipped,
		log:     log,
		now:     time.Now,
		queue:   make(chan Event, queueDepth),
		done:    make(chan struct{}),
	}

	if shipped != nil {
		r.wg.Add(1)
		go r.ship()
	}
	return r
}

func (r *Recorder) Record(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = r.now()
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeAllowed
	}

	if r.durable != nil {
		if err := r.durable.Append(ctx, []Event{e}); err != nil {
			return err
		}
	}

	r.enqueue(e)
	return nil
}

func (r *Recorder) enqueue(e Event) {
	if r.shipped == nil {
		return
	}

	select {
	case r.queue <- e:
	default:
		r.mu.Lock()
		r.dropped++
		dropped := r.dropped
		r.mu.Unlock()

		r.log.Error("audit shipment queue is full, event kept locally only",
			"action", e.Action, "dropped_total", dropped)
	}
}

func (r *Recorder) Dropped() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.dropped
}

func (r *Recorder) ship() {
	defer r.wg.Done()

	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	batch := make([]Event, 0, flushBatch)

	for {
		select {
		case e := <-r.queue:
			batch = append(batch, e)
			if len(batch) >= flushBatch {
				batch = r.flush(batch)
			}

		case <-ticker.C:
			batch = r.flush(batch)

		case <-r.done:
			for {
				select {
				case e := <-r.queue:
					batch = append(batch, e)
				default:
					r.flush(batch)
					return
				}
			}
		}
	}
}

func (r *Recorder) flush(batch []Event) []Event {
	if len(batch) == 0 {
		return batch
	}

	ctx, cancel := context.WithTimeout(context.Background(), shipTimeout)
	defer cancel()

	if err := r.shipped.Append(ctx, batch); err != nil {
		r.log.Error("audit shipment failed, events kept locally only",
			"count", len(batch), "error", err.Error())
	}

	return batch[:0]
}

func (r *Recorder) Close() error {
	if r.shipped == nil {
		return nil
	}

	close(r.done)
	r.wg.Wait()
	return nil
}
