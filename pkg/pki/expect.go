package pki

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// Server kinds accepted by ExpectServer.
const (
	ServerControlPlane = "controlplane"
	ServerEdge         = "edge"
)

// ExpectServer returns a tls.Config.VerifyConnection callback for clients. The callback
// accepts the connection only if:
//
//   - the handshake is TLS 1.3 with the X25519MLKEM768 key exchange (checked inside the
//     handshake, so no request is ever sent over a classic connection);
//   - the server leaf carries exactly one SPIFFE URI SAN, and it is
//     spiffe://opensase/controlplane (kind "controlplane", id must be empty) or
//     spiffe://opensase/edge/<id> (kind "edge", id must be a valid edge ID).
//
// It does not verify the chain itself: that is done by crypto/tls (RootCAs) or by a custom
// VerifyPeerCertificate (pinning), which both run before VerifyConnection. A DNS name check
// alone is not enough, because in dev several server certs may share host names.
// An invalid kind/id combination makes every connection fail.
func ExpectServer(kind, id string) func(tls.ConnectionState) error {
	var want Identity
	var cfgErr error
	switch {
	case kind == ServerControlPlane && id == "":
		want = Identity{Kind: PeerControlPlane}
	case kind == ServerEdge && ValidID(id):
		want = Identity{Kind: PeerEdge, EdgeID: id}
	default:
		cfgErr = fmt.Errorf("pki: ExpectServer: invalid kind %q / id %q", kind, id)
	}
	return func(cs tls.ConnectionState) error {
		if cfgErr != nil {
			return cfgErr
		}
		if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
			return fmt.Errorf("pki: server connection is not post-quantum (version=%#x curve=%v)", cs.Version, cs.CurveID)
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("pki: server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		if len(leaf.URIs) != 1 {
			return ErrNoIdentity
		}
		got, err := ParseURI(leaf.URIs[0].String())
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("pki: server identity is %s %q, want %s %q", got.Kind, got.EdgeID, want.Kind, want.EdgeID)
		}
		return nil
	}
}
