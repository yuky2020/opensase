package saas

import "testing"

func TestLookup(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"www.dropbox.com", "dropbox"},
		{"dropbox.com", "dropbox"},
		{"DL.DropboxUserContent.com.", "dropbox"},
		{"mail.google.com", "gmail"},
		{"drive.google.com", "google-drive"},
		{"docs.google.com", "google-docs"},
		{"www.google.com", ""}, // google.com itself is not one app
		{"notdropbox.com", ""},
		{"dropbox.com.evil.test", ""},
		{"rr3---sn-x.googlevideo.com", "youtube"},
		{"", ""},
	} {
		a, ok := Lookup(tc.host)
		if a.ID != tc.want || ok != (tc.want != "") {
			t.Errorf("Lookup(%q) = %q %v, want %q", tc.host, a.ID, ok, tc.want)
		}
	}
}

func TestCatalog(t *testing.T) {
	apps := Apps()
	if len(apps) != len(catalog) {
		t.Fatal("Apps length")
	}
	apps[0].Domains[0] = "mutated.test"
	if a, _ := ByID(apps[0].ID); a.Domains[0] == "mutated.test" {
		t.Fatal("Apps leaks the catalog")
	}
	for _, c := range Categories() {
		if !IsCategory(c) {
			t.Fatal(c)
		}
	}
	if IsCategory("gambling") {
		t.Fatal("unknown category accepted")
	}
	for _, a := range catalog {
		if a.ID == "" || a.Name == "" || !IsCategory(a.Category) || len(a.Domains) == 0 {
			t.Fatalf("bad app %+v", a)
		}
	}
}
