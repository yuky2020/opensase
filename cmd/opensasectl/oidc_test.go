package main

import (
	"reflect"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
)

func TestParseGroupRoles(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   nil,
			wantErr: true,
		},
		{
			name:  "single valid mapping",
			input: []string{"admins=admin"},
			want: map[string]string{
				"admins": api.TenantRoleAdmin,
			},
		},
		{
			name: "multiple valid mappings",
			input: []string{
				"security-admins=admin",
				"secops=policy-editor",
				"auditors=viewer",
			},
			want: map[string]string{
				"security-admins": api.TenantRoleAdmin,
				"secops":          api.TenantRolePolicyEditor,
				"auditors":        api.TenantRoleViewer,
			},
		},
		{
			name:    "missing separator",
			input:   []string{"admins-admin"},
			wantErr: true,
		},
		{
			name:    "empty group name",
			input:   []string{"=admin"},
			wantErr: true,
		},
		{
			name:    "empty role",
			input:   []string{"admins="},
			wantErr: true,
		},
		{
			name:    "invalid role",
			input:   []string{"admins=superadmin"},
			wantErr: true,
		},
		{
			name: "group with spaces",
			input: []string{
				"Domain Admins=admin",
				"Audit Team=viewer",
			},
			want: map[string]string{
				"Domain Admins": api.TenantRoleAdmin,
				"Audit Team":    api.TenantRoleViewer,
			},
		},
		{
			name: "value containing equals sign in group name",
			input: []string{
				"cn=admins,ou=groups=admin",
			},
			want: map[string]string{
				"cn=admins,ou=groups": api.TenantRoleAdmin,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGroupRoles(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseGroupRoles(%v) err = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseGroupRoles(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
