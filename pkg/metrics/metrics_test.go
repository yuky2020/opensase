package metrics

import (
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	c := r.NewCounter("opensase_test_requests_total", "Requests.", "code")
	c.Inc("200")
	c.Add(2, "500")
	plain := r.NewCounter("opensase_test_events_total", "Events.")
	plain.Inc()
	r.NewGauge("opensase_test_sessions", "Sessions per Edge.", func() []Sample {
		return []Sample{{Labels: map[string]string{"edge": `a"b`}, Value: 3}}
	})
	r.NewGaugeValue("opensase_test_up", "Up.", func() float64 { return 1 })
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP opensase_test_events_total Events.
# TYPE opensase_test_events_total counter
opensase_test_events_total 1
# HELP opensase_test_requests_total Requests.
# TYPE opensase_test_requests_total counter
opensase_test_requests_total{code="200"} 1
opensase_test_requests_total{code="500"} 2
# HELP opensase_test_sessions Sessions per Edge.
# TYPE opensase_test_sessions gauge
opensase_test_sessions{edge="a\"b"} 3
# HELP opensase_test_up Up.
# TYPE opensase_test_up gauge
opensase_test_up 1
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
	var nilC *Counter
	nilC.Inc() // no panic
}
