package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestCIDRList(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "empty",
			args: []string{},
			want: nil,
		},
		{
			name: "single",
			args: []string{"-cidr", "10.0.0.0/24"},
			want: []string{"10.0.0.0/24"},
		},
		{
			name: "multiple",
			args: []string{"-cidr", "10.0.0.0/24", "-cidr", "192.168.1.0/24"},
			want: []string{"10.0.0.0/24", "192.168.1.0/24"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var cidrs cidrList
			fs.Var(&cidrs, "cidr", "authorized CIDR")
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			if tc.want == nil {
				if len(cidrs) != 0 {
					t.Fatalf("got %v, want empty", cidrs)
				}
			} else if !reflect.DeepEqual([]string(cidrs), tc.want) {
				t.Fatalf("got %v, want %v", cidrs, tc.want)
			}
		})
	}
}
