package store

import (
	"context"
	"errors"
	"testing"

	"github.com/yuky2020/opensase/pkg/pki"
)

func TestCAStore(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.GetCA(ctx, "acme", pki.CAKindTenant); !errors.Is(err, pki.ErrCANotFound) {
		t.Fatalf("missing: %v", err)
	}
	first := pki.StoredCA{TenantID: "acme", Kind: pki.CAKindTenant, CertPEM: []byte("cert1"), SealedKey: []byte("key1")}
	second := pki.StoredCA{TenantID: "acme", Kind: pki.CAKindTenant, CertPEM: []byte("cert2"), SealedKey: []byte("key2")}
	for _, c := range []pki.StoredCA{first, second} {
		if err := s.InsertCA(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetCA(ctx, "acme", pki.CAKindTenant)
	if err != nil || string(got.CertPEM) != "cert1" || string(got.SealedKey) != "key1" {
		t.Fatalf("first row must win: %+v %v", got, err)
	}
	if err := s.InsertCA(ctx, pki.StoredCA{TenantID: "acme", Kind: pki.CAKindInspection, CertPEM: []byte("i"), SealedKey: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCAs(ctx, pki.CAKindTenant)
	if err != nil || len(list) != 1 || list[0].TenantID != "acme" {
		t.Fatalf("list %+v %v", list, err)
	}
}
