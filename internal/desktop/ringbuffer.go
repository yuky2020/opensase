package desktop

import (
	"sync"
)

// Event represents an engine event recorded by the daemon.
type Event struct {
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
}

// ringBuffer stores the last N events in FIFO order.
type ringBuffer struct {
	mu     sync.RWMutex
	buf    []Event
	cap    int
	start  int
	length int
}

func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = 200
	}
	return &ringBuffer{
		buf: make([]Event, size),
		cap: size,
	}
}

func (r *ringBuffer) Add(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.length < r.cap {
		r.buf[(r.start+r.length)%r.cap] = e
		r.length++
	} else {
		r.buf[r.start] = e
		r.start = (r.start + 1) % r.cap
	}
}

func (r *ringBuffer) Snapshot() []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Event, r.length)
	for i := 0; i < r.length; i++ {
		out[i] = r.buf[(r.start+i)%r.cap]
	}
	return out
}
