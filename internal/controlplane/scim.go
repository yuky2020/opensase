package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yuky2020/opensase/pkg/store"
)

// SCIM 2.0 (RFC 7643, RFC 7644) for users and groups (issue #68): the identity provider
// creates, updates and deactivates users and groups at /scim/v2/{tenant}, authenticated by
// the tenant's bearer token. Deactivating or deleting a user revokes their devices at once;
// group changes recompile the snapshots of the members, whose rules may depend on groups.

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimErrSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimTokenPrefix = "osscim_"
)

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

type scimUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Meta        *scimMeta   `json:"meta,omitempty"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
	Meta        *scimMeta    `json:"meta,omitempty"`
}

type scimPatch struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path,omitempty"`
		Value json.RawMessage `json:"value,omitempty"`
	} `json:"Operations"`
}

func scimErr(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{scimErrSchema}, "status": strconv.Itoa(code), "detail": detail})
}

func scimJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type scimTenantKey struct{}

// requireSCIM checks the tenant's bearer token.
func (s *Server) requireSCIM(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(tok, scimTokenPrefix) {
			scimErr(w, http.StatusUnauthorized, "bearer token required")
			return
		}
		h := sha256.Sum256([]byte(tok))
		tenant, err := s.cfg.Store.TenantBySCIMToken(r.Context(), h[:])
		if err != nil || tenant != chi.URLParam(r, "tenant") {
			scimErr(w, http.StatusUnauthorized, "invalid token for this tenant")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), scimTenantKey{}, tenant)))
	})
}

func scimTenant(r *http.Request) string {
	t, _ := r.Context().Value(scimTenantKey{}).(string)
	return t
}

func (s *Server) scimRoutes(r chi.Router) {
	r.Use(s.requireSCIM)
	r.Get("/Users", s.scimListUsers)
	r.Post("/Users", s.scimCreateUser)
	r.Get("/Users/{id}", s.scimGetUser)
	r.Put("/Users/{id}", s.scimReplaceUser)
	r.Patch("/Users/{id}", s.scimPatchUser)
	r.Delete("/Users/{id}", s.scimDeleteUser)
	r.Get("/Groups", s.scimListGroups)
	r.Post("/Groups", s.scimCreateGroup)
	r.Get("/Groups/{id}", s.scimGetGroup)
	r.Put("/Groups/{id}", s.scimReplaceGroup)
	r.Patch("/Groups/{id}", s.scimPatchGroup)
	r.Delete("/Groups/{id}", s.scimDeleteGroup)
}

var scimFilterRe = regexp.MustCompile(`^(userName|externalId|displayName) eq "([^"]*)"$`)

func toSCIMUser(u store.SCIMUser) scimUser {
	active := u.Active
	return scimUser{Schemas: []string{scimUserSchema}, ID: u.ID, ExternalID: u.ExternalID, UserName: u.Email,
		DisplayName: u.Name, Emails: []scimEmail{{Value: u.Email, Primary: true}}, Active: &active,
		Meta: &scimMeta{ResourceType: "User"}}
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	attr, value := "", ""
	if f := r.URL.Query().Get("filter"); f != "" {
		m := scimFilterRe.FindStringSubmatch(f)
		if m == nil || m[1] == "displayName" {
			scimErr(w, http.StatusBadRequest, "only userName eq and externalId eq filters are supported")
			return
		}
		attr, value = m[1], m[2]
	}
	users, err := s.cfg.Store.ListSCIMUsers(r.Context(), scimTenant(r), attr, value)
	if err != nil {
		s.internalErr(w, r, "scim users", err)
		return
	}
	res := make([]scimUser, 0, len(users))
	for _, u := range users {
		res = append(res, toSCIMUser(u))
	}
	scimJSON(w, http.StatusOK, scimPage(r, res))
}

// scimPage applies startIndex and count (1-based, RFC 7644 §3.4.2.4).
func scimPage[T any](r *http.Request, all []T) map[string]any {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count < 0 || count > 500 {
		count = 500
	}
	start = max(start, 1)
	page := []T{}
	if start-1 < len(all) {
		page = all[start-1 : min(len(all), start-1+count)]
	}
	return map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(all), "startIndex": start, "itemsPerPage": len(page), "Resources": page}
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.cfg.Store.GetSCIMUser(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such user")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim user", err)
		return
	}
	scimJSON(w, http.StatusOK, toSCIMUser(u))
}

func decodeSCIM(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func (in scimUser) email() string {
	for _, e := range in.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(in.Emails) > 0 {
		return in.Emails[0].Value
	}
	return in.UserName
}

func (in scimUser) displayName() string {
	if in.DisplayName != "" {
		return in.DisplayName
	}
	if in.Name != nil {
		if in.Name.Formatted != "" {
			return in.Name.Formatted
		}
		if n := strings.TrimSpace(in.Name.GivenName + " " + in.Name.FamilyName); n != "" {
			return n
		}
	}
	return in.UserName
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if !decodeSCIM(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		scimErr(w, http.StatusBadRequest, "userName is required")
		return
	}
	t := scimTenant(r)
	if _, err := s.cfg.Store.UserByEmail(r.Context(), t, in.email()); err == nil {
		scimErr(w, http.StatusConflict, "a user with this userName exists")
		return
	}
	u := store.SCIMUser{User: store.User{ID: uuid.NewString(), TenantID: t, Email: in.email(), Name: in.displayName()}, ExternalID: in.ExternalID, Active: in.Active == nil || *in.Active}
	if err := s.cfg.Store.PutSCIMUser(r.Context(), u); err != nil {
		s.internalErr(w, r, "scim create user", err)
		return
	}
	scimJSON(w, http.StatusCreated, toSCIMUser(u))
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if !decodeSCIM(w, r, &in) {
		return
	}
	cur, ok := s.scimUser(w, r)
	if !ok {
		return
	}
	cur.Email, cur.Name, cur.ExternalID = in.email(), in.displayName(), in.ExternalID
	cur.Active = in.Active == nil || *in.Active
	s.saveSCIMUser(w, r, cur)
}

func (s *Server) scimUser(w http.ResponseWriter, r *http.Request) (store.SCIMUser, bool) {
	u, err := s.cfg.Store.GetSCIMUser(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such user")
		return u, false
	}
	if err != nil {
		s.internalErr(w, r, "scim user", err)
		return u, false
	}
	return u, true
}

// saveSCIMUser stores u and revokes the devices of a deactivated user.
func (s *Server) saveSCIMUser(w http.ResponseWriter, r *http.Request, u store.SCIMUser) {
	if err := s.cfg.Store.PutSCIMUser(r.Context(), u); err != nil {
		s.internalErr(w, r, "scim save user", err)
		return
	}
	if !u.Active {
		if err := s.revokeUser(r.Context(), u.TenantID, u.ID); err != nil {
			s.internalErr(w, r, "revoke devices", err)
			return
		}
	}
	scimJSON(w, http.StatusOK, toSCIMUser(u))
}

// revokeUser revokes every device of a user and wakes their long-polls.
func (s *Server) revokeUser(ctx context.Context, tenantID, userID string) error {
	ids, err := s.cfg.Store.RevokeUserDevices(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		s.wake(ctx, id)
	}
	if len(ids) > 0 {
		s.log.InfoContext(ctx, "user deprovisioned; devices revoked", "tenant", tenantID, "user", userID, "devices", len(ids))
	}
	return nil
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	var p scimPatch
	if !decodeSCIM(w, r, &p) {
		return
	}
	u, ok := s.scimUser(w, r)
	if !ok {
		return
	}
	for _, op := range p.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			scimErr(w, http.StatusBadRequest, "only add and replace operations are supported on users")
			return
		}
		fields := map[string]json.RawMessage{}
		if op.Path != "" {
			fields[op.Path] = op.Value
		} else if err := json.Unmarshal(op.Value, &fields); err != nil {
			scimErr(w, http.StatusBadRequest, "invalid operation value")
			return
		}
		for path, raw := range fields {
			var sv string
			switch path {
			case "active":
				var b bool
				if json.Unmarshal(raw, &b) != nil {
					// Some providers send "False" as a string.
					if json.Unmarshal(raw, &sv) != nil {
						scimErr(w, http.StatusBadRequest, "active must be a boolean")
						return
					}
					b = strings.EqualFold(sv, "true")
				}
				u.Active = b
			case "userName":
				_ = json.Unmarshal(raw, &u.Email)
			case "displayName":
				_ = json.Unmarshal(raw, &u.Name)
			case "externalId":
				_ = json.Unmarshal(raw, &u.ExternalID)
			}
		}
	}
	s.saveSCIMUser(w, r, u)
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	t, id := scimTenant(r), chi.URLParam(r, "id")
	if err := s.revokeUser(r.Context(), t, id); err != nil {
		s.internalErr(w, r, "revoke devices", err)
		return
	}
	err := s.cfg.Store.DeleteUser(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such user")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toSCIMGroup(g store.SCIMGroup) scimGroup {
	out := scimGroup{Schemas: []string{scimGroupSchema}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.DisplayName, Members: []scimMember{}, Meta: &scimMeta{ResourceType: "Group"}}
	for _, m := range g.Members {
		out.Members = append(out.Members, scimMember{Value: m})
	}
	return out
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	name := ""
	if f := r.URL.Query().Get("filter"); f != "" {
		m := scimFilterRe.FindStringSubmatch(f)
		if m == nil || m[1] != "displayName" {
			scimErr(w, http.StatusBadRequest, "only the displayName eq filter is supported")
			return
		}
		name = m[2]
	}
	gs, err := s.cfg.Store.ListSCIMGroups(r.Context(), scimTenant(r), name)
	if err != nil {
		s.internalErr(w, r, "scim groups", err)
		return
	}
	res := make([]scimGroup, 0, len(gs))
	for _, g := range gs {
		res = append(res, toSCIMGroup(g))
	}
	scimJSON(w, http.StatusOK, scimPage(r, res))
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.cfg.Store.GetSCIMGroup(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such group")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim group", err)
		return
	}
	scimJSON(w, http.StatusOK, toSCIMGroup(g))
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroup
	if !decodeSCIM(w, r, &in) {
		return
	}
	g := store.SCIMGroup{ID: uuid.NewString(), TenantID: scimTenant(r), DisplayName: strings.TrimSpace(in.DisplayName), ExternalID: in.ExternalID}
	for _, m := range in.Members {
		g.Members = append(g.Members, m.Value)
	}
	s.saveSCIMGroup(w, r, g, http.StatusCreated)
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroup
	if !decodeSCIM(w, r, &in) {
		return
	}
	cur, err := s.cfg.Store.GetSCIMGroup(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such group")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim group", err)
		return
	}
	cur.DisplayName, cur.ExternalID, cur.Members = strings.TrimSpace(in.DisplayName), in.ExternalID, nil
	for _, m := range in.Members {
		cur.Members = append(cur.Members, m.Value)
	}
	s.saveSCIMGroup(w, r, cur, http.StatusOK)
}

var scimMemberPathRe = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	var p scimPatch
	if !decodeSCIM(w, r, &p) {
		return
	}
	g, err := s.cfg.Store.GetSCIMGroup(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such group")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim group", err)
		return
	}
	for _, op := range p.Operations {
		var members []scimMember
		switch {
		case op.Path == "members" || op.Path == "":
			if op.Path == "" {
				var v struct {
					DisplayName string       `json:"displayName"`
					Members     []scimMember `json:"members"`
				}
				_ = json.Unmarshal(op.Value, &v)
				if v.DisplayName != "" {
					g.DisplayName = v.DisplayName
				}
				members = v.Members
			} else if len(op.Value) > 0 {
				_ = json.Unmarshal(op.Value, &members)
			}
		case op.Path == "displayName":
			_ = json.Unmarshal(op.Value, &g.DisplayName)
			continue
		case scimMemberPathRe.MatchString(op.Path):
			members = []scimMember{{Value: scimMemberPathRe.FindStringSubmatch(op.Path)[1]}}
		default:
			scimErr(w, http.StatusBadRequest, "unsupported path "+op.Path)
			return
		}
		switch strings.ToLower(op.Op) {
		case "add":
			for _, m := range members {
				if !slices.Contains(g.Members, m.Value) {
					g.Members = append(g.Members, m.Value)
				}
			}
		case "remove":
			if op.Path == "members" && len(members) == 0 {
				g.Members = nil
			}
			for _, m := range members {
				g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return x == m.Value })
			}
		case "replace":
			if op.Path == "members" || members != nil {
				g.Members = nil
				for _, m := range members {
					g.Members = append(g.Members, m.Value)
				}
			}
		default:
			scimErr(w, http.StatusBadRequest, "unsupported operation "+op.Op)
			return
		}
	}
	s.saveSCIMGroup(w, r, g, http.StatusOK)
}

func (s *Server) saveSCIMGroup(w http.ResponseWriter, r *http.Request, g store.SCIMGroup, code int) {
	if g.DisplayName == "" {
		scimErr(w, http.StatusBadRequest, "displayName is required")
		return
	}
	changed, err := s.cfg.Store.PutSCIMGroup(r.Context(), g)
	if errors.Is(err, store.ErrConflict) {
		scimErr(w, http.StatusConflict, "a group with this displayName exists")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim save group", err)
		return
	}
	s.recompileUsers(r.Context(), g.TenantID, changed)
	g, err = s.cfg.Store.GetSCIMGroup(r.Context(), g.TenantID, g.ID)
	if err != nil {
		s.internalErr(w, r, "scim group", err)
		return
	}
	scimJSON(w, code, toSCIMGroup(g))
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	members, err := s.cfg.Store.DeleteSCIMGroup(r.Context(), scimTenant(r), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		scimErr(w, http.StatusNotFound, "no such group")
		return
	}
	if err != nil {
		s.internalErr(w, r, "scim delete group", err)
		return
	}
	s.recompileUsers(r.Context(), scimTenant(r), members)
	w.WriteHeader(http.StatusNoContent)
}

// recompileUsers rebuilds the snapshots of the users' devices after a group change.
func (s *Server) recompileUsers(ctx context.Context, tenantID string, users []string) {
	for _, u := range users {
		devs, err := s.cfg.Store.ListDevices(ctx, store.DeviceFilter{TenantID: tenantID, UserID: u})
		if err == nil && len(devs) > 0 {
			_, err = s.compileDevices(ctx, tenantID, devs)
		}
		if err != nil {
			s.log.WarnContext(ctx, "snapshots not recompiled after a group change", "tenant", tenantID, "user", u, "err", err)
		}
	}
}

// handleCreateSCIMToken creates (or replaces) the tenant's SCIM bearer token. The token is
// shown once.
func (s *Server) handleCreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	t := chi.URLParam(r, "t")
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	tok := scimTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	h := sha256.Sum256([]byte(tok))
	if err := s.cfg.Store.SetSCIMToken(r.Context(), t, h[:]); err != nil {
		s.internalErr(w, r, "scim token", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": tok, "baseUrl": strings.TrimSuffix(s.cfg.ControlURL, "/") + "/scim/v2/" + t})
}
