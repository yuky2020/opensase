package edge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/packet"
)

func TestEdgePeerFeedRoutes_AllowedIPs(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)

	// Configure initial routes for peers.
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		switch fx.cp.peers.Devices[i].DeviceID {
		case "d1":
			fx.cp.peers.Devices[i].Routes = []string{"10.30.0.0/24"}
		case "d2":
			fx.cp.peers.Devices[i].Routes = []string{"10.40.0.0/24"}
		}
	}
	fx.cp.mu.Unlock()

	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatalf("syncPeers failed: %v", err)
	}

	srv := fx.sessionServer()

	// Establish session for d1.
	cert1 := fx.deviceCert("acme", "d1")
	c1 := fx.client(&cert1)
	wgKey1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub1 := wgKey1.PublicKey().Bytes()

	code, _, _ := postSession(t, c1, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub1)})
	if code != 200 {
		t.Fatalf("d1 session: %d", code)
	}

	// Establish session for d2.
	cert2 := fx.deviceCert("acme", "d2")
	c2 := fx.client(&cert2)
	wgKey2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub2 := wgKey2.PublicKey().Bytes()

	code, _, _ = postSession(t, c2, srv.URL, api.SessionRequest{WGPublicKey: base64.StdEncoding.EncodeToString(pub2)})
	if code != 200 {
		t.Fatalf("d2 session: %d", code)
	}

	// Verify WireGuard UAPI allowed IPs.
	fx.wg.mu.Lock()
	ops := append([]string(nil), fx.wg.ops...)
	fx.wg.mu.Unlock()

	pub1Hex := hex.EncodeToString(pub1)
	pub2Hex := hex.EncodeToString(pub2)

	var d1Op, d2Op string
	for _, op := range ops {
		if strings.Contains(op, "public_key="+pub1Hex) {
			d1Op = op
		}
		if strings.Contains(op, "public_key="+pub2Hex) {
			d2Op = op
		}
	}

	if !strings.Contains(d1Op, "allowed_ip=10.30.0.0/24") {
		t.Errorf("d1 uapi op missing allowed_ip=10.30.0.0/24: %q", d1Op)
	}
	if strings.Contains(d1Op, "allowed_ip=10.40.0.0/24") {
		t.Errorf("d1 uapi op unexpectedly contained d2's route: %q", d1Op)
	}

	if !strings.Contains(d2Op, "allowed_ip=10.40.0.0/24") {
		t.Errorf("d2 uapi op missing allowed_ip=10.40.0.0/24: %q", d2Op)
	}
	if strings.Contains(d2Op, "allowed_ip=10.30.0.0/24") {
		t.Errorf("d2 uapi op unexpectedly contained d1's route: %q", d2Op)
	}

	// Update d1's route at next peer sync.
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		if fx.cp.peers.Devices[i].DeviceID == "d1" {
			fx.cp.peers.Devices[i].Routes = []string{"10.50.0.0/24"}
		}
	}
	fx.cp.mu.Unlock()

	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatalf("syncPeers update failed: %v", err)
	}

	fx.wg.mu.Lock()
	ops = append([]string(nil), fx.wg.ops...)
	fx.wg.mu.Unlock()

	var lastD1Op string
	for _, op := range ops {
		if strings.Contains(op, "public_key="+pub1Hex) {
			lastD1Op = op
		}
	}

	if !strings.Contains(lastD1Op, "allowed_ip=10.50.0.0/24") {
		t.Errorf("d1 uapi update missing new route 10.50.0.0/24: %q", lastD1Op)
	}
	if strings.Contains(lastD1Op, "allowed_ip=10.30.0.0/24") {
		t.Errorf("d1 uapi update still contained old route 10.30.0.0/24: %q", lastD1Op)
	}

	// Remove routes for d1; should be removed from allowed IPs at next sync.
	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		if fx.cp.peers.Devices[i].DeviceID == "d1" {
			fx.cp.peers.Devices[i].Routes = nil
		}
	}
	fx.cp.mu.Unlock()

	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatalf("syncPeers clear failed: %v", err)
	}

	fx.wg.mu.Lock()
	ops = append([]string(nil), fx.wg.ops...)
	fx.wg.mu.Unlock()

	for _, op := range ops {
		if strings.Contains(op, "public_key="+pub1Hex) {
			lastD1Op = op
		}
	}

	if strings.Contains(lastD1Op, "allowed_ip=10.50.0.0/24") {
		t.Errorf("d1 uapi clear still contained route 10.50.0.0/24: %q", lastD1Op)
	}
	if !strings.Contains(lastD1Op, "allowed_ip=100.64.0.") {
		t.Errorf("d1 uapi clear missing tunnel IP: %q", lastD1Op)
	}
}

func TestEdgeFilter_RoutedWorkload(t *testing.T) {
	fx := newFixture(t)
	fx.setPeer("d1", 1)
	fx.setPeer("d2", 1)

	fx.cp.mu.Lock()
	for i := range fx.cp.peers.Devices {
		switch fx.cp.peers.Devices[i].DeviceID {
		case "d1":
			fx.cp.peers.Devices[i].Routes = []string{"10.30.0.0/24"}
		case "d2":
			fx.cp.peers.Devices[i].Routes = []string{"10.40.0.0/24"}
		}
	}
	fx.cp.mu.Unlock()

	if err := fx.e.syncPeers(context.Background()); err != nil {
		t.Fatalf("syncPeers failed: %v", err)
	}

	d1 := fx.e.reg.get("d1")
	d2 := fx.e.reg.get("d2")
	fx.e.reg.mu.Lock()
	_ = fx.e.reg.allocateLocked(d1)
	_ = fx.e.reg.allocateLocked(d2)
	fx.e.reg.mu.Unlock()

	ft := newFakeTUN()
	f := newFilter(ft, fx.e)
	defer f.Close()
	rd := startReader(f)

	write := func(pkt []byte) bool {
		before := ft.nWrites()
		if _, err := f.Write([][]byte{pkt}, 0); err != nil {
			t.Fatal(err)
		}
		return ft.nWrites() > before
	}

	// 1. Packet from peer with source in its route accepted.
	workloadSrc := "10.30.0.15"
	targetDst := "93.184.215.14"
	syn := ipv4(workloadSrc, targetDst, packet.ProtoTCP, tcpSeg(40000, 443, packet.FlagSYN))
	if !write(syn) {
		t.Fatal("SYN from authorized workload source dropped")
	}

	// 2. Reply to route address goes to the right peer.
	ft.in <- ipv4(targetDst, workloadSrc, packet.ProtoTCP, tcpSeg(443, 40000, packet.FlagSYN|packet.FlagACK))
	reply, ok := readOne(t, rd)
	if !ok {
		t.Fatal("SYN-ACK reply to workload address dropped")
	}
	var p packet.Packet
	if err := packet.Parse(reply, &p); err != nil || p.Dst.String() != workloadSrc {
		t.Fatalf("reply destination: got %v err %v, want %s", p.Dst, err, workloadSrc)
	}

	// 3. Source outside any route refused.
	unauthorizedSrc := "10.99.0.5"
	if write(ipv4(unauthorizedSrc, targetDst, packet.ProtoTCP, tcpSeg(40001, 443, packet.FlagSYN))) {
		t.Fatal("traffic from unauthorized source passed")
	}

	// 4. Source in another peer's route attributed to the other peer (d2), not d1.
	d2WorkloadSrc := "10.40.0.20"
	ownerDev := fx.e.reg.byTunnelIP(p.Dst) // workloadSrc (10.30.0.15) -> d1
	if ownerDev == nil || ownerDev.id != "d1" {
		t.Fatalf("owner of %s: got %v, want d1", workloadSrc, ownerDev)
	}
	ownerD2 := fx.e.reg.byTunnelIP(netip.MustParseAddr(d2WorkloadSrc))
	if ownerD2 == nil || ownerD2.id != "d2" {
		t.Fatalf("owner of %s: got %v, want d2", d2WorkloadSrc, ownerD2)
	}

	// Peer address ownership / anti-spoofing checks.
	if !d1.ownsAddress(netip.MustParseAddr(workloadSrc)) {
		t.Fatalf("d1 should own its routed address %s", workloadSrc)
	}
	if d1.ownsAddress(netip.MustParseAddr(d2WorkloadSrc)) {
		t.Fatalf("d1 should NOT own d2's routed address %s", d2WorkloadSrc)
	}
	if d1.ownsAddress(netip.MustParseAddr(unauthorizedSrc)) {
		t.Fatalf("d1 should NOT own unrouted address %s", unauthorizedSrc)
	}
	if !d2.ownsAddress(netip.MustParseAddr(d2WorkloadSrc)) {
		t.Fatalf("d2 should own its routed address %s", d2WorkloadSrc)
	}

	// 5. Unsolicited inbound to a route address is dropped.
	ft.in <- ipv4("6.6.6.6", workloadSrc, packet.ProtoTCP, tcpSeg(443, 40002, packet.FlagSYN))
	if _, ok := readOne(t, rd); ok {
		t.Fatal("unsolicited inbound to workload address passed")
	}

	// 6. Flows keep workload source address: close flow and sweep.
	write(ipv4(workloadSrc, targetDst, packet.ProtoTCP, tcpSeg(40000, 443, packet.FlagRST)))
	recs := fx.e.ct.sweep(time.Now().Add(time.Minute), fx.e.owner)
	var found bool
	for _, r := range recs {
		if r.Flow.DstIP == targetDst && r.DeviceID == "d1" && r.BytesOut > 0 && r.BytesIn > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("flow record for routed workload not found in swept records: %+v", recs)
	}
}
