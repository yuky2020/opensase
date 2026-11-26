package controlplane

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/categories"
	"github.com/yuky2020/opensase/pkg/dlp"
	"github.com/yuky2020/opensase/pkg/store"
)

// DLP datasets (ADR-0029, issue #15). Values and documents are hashed here, with a random key
// per dataset, and discarded; only the hashes are stored and sent to the Edges that serve the
// tenant.

const (
	maxDatasetBody    = 32 << 20
	maxDatasetEntries = 500_000
)

func (s *Server) handlePutDataset(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	name := chi.URLParam(r, "name")
	if !categories.ValidName(name) {
		writeErr(w, http.StatusBadRequest, "invalid dataset name")
		return
	}
	setDeadline(w, routeTimeout*2)
	var req api.DLPDatasetRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDatasetBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		s.internalErr(w, r, "random", err)
		return
	}
	var hashes []uint64
	switch req.Kind {
	case dlp.KindRecords:
		if len(req.Values) > 0 || len(req.Documents) > 0 {
			writeErr(w, http.StatusBadRequest, "a records dataset takes records, not values or documents")
			return
		}
		hashes = dlp.RecordHashes(key, req.Records)
	case dlp.KindValues:
		if len(req.Documents) > 0 || len(req.Records) > 0 {
			writeErr(w, http.StatusBadRequest, "a values dataset takes values, not documents")
			return
		}
		hashes = dlp.ValueHashes(key, req.Values)
	case dlp.KindDocument:
		if len(req.Values) > 0 || len(req.Records) > 0 {
			writeErr(w, http.StatusBadRequest, "a document dataset takes documents, not values")
			return
		}
		for _, doc := range req.Documents {
			// The text of Office, PDF and archive files, as the Edge will see it (ADR-0021).
			var text bytes.Buffer
			for _, b := range dlp.Extract(doc).Blobs {
				text.Write(b)
				text.WriteByte(' ')
			}
			hashes = append(hashes, dlp.ShingleHashes(key, text.String())...)
		}
		slices.Sort(hashes)
		hashes = slices.Compact(hashes)
	default:
		writeErr(w, http.StatusBadRequest, "kind must be values, document or records")
		return
	}
	kind := req.Kind
	req = api.DLPDatasetRequest{} // drop the content as early as possible
	if len(hashes) == 0 {
		writeErr(w, http.StatusBadRequest, "nothing to protect: no usable value or document text")
		return
	}
	if len(hashes) > maxDatasetEntries {
		writeErr(w, http.StatusRequestEntityTooLarge, "dataset larger than 500000 entries")
		return
	}
	d := store.Dataset{TenantID: t, Name: name, Kind: kind, Key: key, Hashes: hashes, UpdatedAt: s.now().UTC()}
	if err := s.cfg.Store.PutDataset(r.Context(), d); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		s.internalErr(w, r, "store dataset", err)
		return
	}
	writeJSON(w, http.StatusOK, api.DLPDataset{Name: name, Kind: d.Kind, Entries: len(hashes), UpdatedAt: d.UpdatedAt})
}

func (s *Server) handleListDatasets(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	ds, err := s.cfg.Store.ListDatasets(r.Context(), t)
	if err != nil {
		s.internalErr(w, r, "list datasets", err)
		return
	}
	out := make([]api.DLPDataset, 0, len(ds))
	for _, d := range ds {
		out = append(out, api.DLPDataset{Name: d.Name, Kind: d.Kind, Entries: d.Count, UpdatedAt: d.UpdatedAt.UTC()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteDataset(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	err := s.cfg.Store.DeleteDataset(r.Context(), t, chi.URLParam(r, "name"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "unknown dataset")
	case err != nil:
		s.internalErr(w, r, "delete dataset", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleEdgeDatasets sends an Edge the named datasets of a tenant it serves.
func (s *Server) handleEdgeDatasets(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	tenant := r.URL.Query().Get("tenant")
	edge, err := s.cfg.Store.GetEdge(r.Context(), p.id.EdgeID)
	if err != nil {
		s.internalErr(w, r, "edge", err)
		return
	}
	if edge.TenantID != "" && edge.TenantID != tenant {
		writeErr(w, http.StatusForbidden, "edge does not serve this tenant")
		return
	}
	var names []string
	for _, n := range strings.Split(r.URL.Query().Get("names"), ",") {
		if n = strings.TrimSpace(n); categories.ValidName(n) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if tenant == "" || len(names) == 0 || len(names) > 64 {
		writeErr(w, http.StatusBadRequest, "tenant and 1..64 dataset names required")
		return
	}
	ds, err := s.cfg.Store.GetDatasets(r.Context(), tenant, names)
	if err != nil {
		s.internalErr(w, r, "datasets", err)
		return
	}
	out := api.EdgeDatasets{Datasets: []api.EdgeDataset{}}
	for _, d := range ds {
		b := make([]byte, 8*len(d.Hashes))
		for i, h := range d.Hashes {
			binary.BigEndian.PutUint64(b[8*i:], h)
		}
		out.Datasets = append(out.Datasets, api.EdgeDataset{Name: d.Name, Kind: d.Kind, Key: d.Key, Hashes: b})
	}
	setDeadline(w, routeTimeout*2)
	writeJSON(w, http.StatusOK, out)
}
