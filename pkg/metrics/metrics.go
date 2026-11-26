// Package metrics exposes counters and gauges in the Prometheus text format (issue #73),
// without a client library: the Control Plane and the Edge need a handful of series.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds the series of one process. It is safe for concurrent use.
type Registry struct {
	mu     sync.Mutex
	series map[string]*family
}

type family struct {
	help, kind string
	mu         sync.Mutex
	counters   map[string]*atomic.Uint64 // label string -> value; guarded by mu
	gauge      func() []Sample
}

// Sample is one gauge value with its labels.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// New returns an empty registry.
func New() *Registry { return &Registry{series: map[string]*family{}} }

// Counter is a monotonically increasing series with fixed label names.
type Counter struct {
	f      *family
	labels []string
}

// NewCounter registers a counter. labels are the label names, in order.
func (r *Registry) NewCounter(name, help string, labels ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := &family{help: help, kind: "counter", counters: map[string]*atomic.Uint64{}}
	r.series[name] = f
	if len(labels) == 0 {
		f.counters[""] = &atomic.Uint64{}
	}
	return &Counter{f: f, labels: labels}
}

// Add adds n to the series with these label values (one per label name).
func (c *Counter) Add(n uint64, values ...string) {
	if c == nil {
		return
	}
	key := labelString(c.labels, values)
	c.f.counterFor(key).Add(n)
}

// Inc adds one.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

func (f *family) counterFor(key string) *atomic.Uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.counters[key]
	if !ok {
		v = &atomic.Uint64{}
		f.counters[key] = v
	}
	return v
}

// NewGauge registers a gauge whose samples fn computes at scrape time.
func (r *Registry) NewGauge(name, help string, fn func() []Sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.series[name] = &family{help: help, kind: "gauge", gauge: fn}
}

// NewGaugeValue registers a gauge with one unlabelled value.
func (r *Registry) NewGaugeValue(name, help string, fn func() float64) {
	r.NewGauge(name, help, func() []Sample { return []Sample{{Value: fn()}} })
}

// WriteTo writes every series in the text exposition format, sorted by name.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.series))
	for n := range r.series {
		names = append(names, n)
	}
	fams := make(map[string]*family, len(r.series))
	for n, f := range r.series {
		fams[n] = f
	}
	r.mu.Unlock()
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		f := fams[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", n, escapeHelp(f.help), n, f.kind)
		if f.kind == "counter" {
			f.mu.Lock()
			keys := make([]string, 0, len(f.counters))
			for k := range f.counters {
				keys = append(keys, k)
			}
			f.mu.Unlock()
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "%s%s %d\n", n, k, f.counterFor(k).Load())
			}
			continue
		}
		for _, s := range f.gauge() {
			names := make([]string, 0, len(s.Labels))
			for k := range s.Labels {
				names = append(names, k)
			}
			sort.Strings(names)
			vals := make([]string, len(names))
			for i, k := range names {
				vals[i] = s.Labels[k]
			}
			fmt.Fprintf(&b, "%s%s %s\n", n, labelString(names, vals), strconv.FormatFloat(s.Value, 'g', -1, 64))
		}
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Handler serves the registry at /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = r.WriteTo(w)
	})
}

func labelString(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(values) {
			v = values[i]
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(v))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}
