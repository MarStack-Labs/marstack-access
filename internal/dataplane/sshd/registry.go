package sshd

import (
	"context"
	"sync"
)

type registry struct {
	mu   sync.Mutex
	live map[string]context.CancelFunc
}

func newRegistry() *registry {
	return &registry{live: map[string]context.CancelFunc{}}
}

func (r *registry) add(id string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.live[id] = cancel
}

func (r *registry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.live, id)
}

func (r *registry) kill(id string) bool {
	r.mu.Lock()
	cancel, ok := r.live[id]
	r.mu.Unlock()

	if !ok {
		return false
	}

	cancel()
	return true
}

func (r *registry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.live)
}
