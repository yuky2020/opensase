// Package mobile is the gomobile-bound API of the Client core.
// Build: gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -javapkg eu.opensase.core -o clients/android/app/libs/opensase-core.aar ./mobile
//
// CONTRACT FILE between Go core and the Android app. gomobile restrictions apply: only
// string, bool, int/int32/int64, float64, []byte, error, exported structs of those,
// and interfaces whose methods use those types.
//
// Threading: every Engine method is safe to call from any thread. Platform callbacks are
// called from Go goroutines; implementations must not block for more than a few ms.
package mobile

// Platform is implemented in Kotlin (eu.opensase.android.core.PlatformBridge).
type Platform interface {
	// ConnectionOwnerUID returns the Linux UID owning the connection, or -1 if unknown.
	// protocol is 6 (TCP) or 17 (UDP). Kotlin calls ConnectivityManager.getConnectionOwnerUid.
	ConnectionOwnerUID(protocol int, srcIP string, srcPort int, dstIP string, dstPort int) int
	// PackagesForUID returns the comma-separated package names for a UID ("" if none).
	PackagesForUID(uid int) string
	// Protect excludes a socket fd from the VPN (VpnService.protect). Needed for sockets the
	// core opens itself, even though the app is also excluded via addDisallowedApplication.
	Protect(fd int) bool
	// OnEvent delivers asynchronous events. kind: "state","flow","stats","snapshot","error","log".
	// payload is JSON (see docs/mobile-client.md, "Events").
	OnEvent(kind string, payload string)
}

// Engine methods (implemented in engine.go):
//
//	func NewEngine(stateDir string, platform Platform) (*Engine, error)
//	    stateDir: app-private dir for keys, certs, cached snapshot (survives restarts).
//
//	func (e *Engine) IsEnrolled() bool
//	func (e *Engine) Enroll(controlURL, provisioningKey, deviceName string) error
//	    Generates the device key (ECDSA P-256) + CSR, calls POST /v1/enroll, stores cert, CA, edges, keys.
//	func (e *Engine) Unenroll() error
//
//	func (e *Engine) Start(tunFd int, networkType string) error
//	    Takes ownership of tunFd. Runs: session setup with the Edge (PQ PSK), wireguard-go with
//	    FilteringTUN, DNS interceptor, snapshot long-poll, flow log upload, PSK rotation.
//	func (e *Engine) Stop()
//	func (e *Engine) SetNetworkType(networkType string)     // "wifi","cellular","roaming","ethernet","unknown"
//
//	func (e *Engine) TunnelConfig() (string, error)
//	    JSON {"ipv4":"100.64.0.7/32","ipv6":"fd7a:5a5e::7/128","dns":["100.64.0.1"],"mtu":1280}
//	    Kotlin calls this BEFORE building the VpnService interface; it performs session setup.
//
//	func (e *Engine) Snapshot() string          // current snapshot JSON (unsigned payload) or ""
//	func (e *Engine) SetUserRules(json string) error   // api.UserRules JSON -> PUT /v1/self/rules
//	func (e *Engine) SetAppPolicy(pkg string, wifi, cellular, roaming string) error // convenience over SetUserRules
//	func (e *Engine) RecentFlows(limit int) string     // JSON []api.FlowRecord, newest first
//	func (e *Engine) AppStats() string                 // JSON [{"app":..,"bytesIn":..,"bytesOut":..,"allowed":..,"blocked":..}]
//	func (e *Engine) Status() string                   // JSON {"state":"connected|connecting|stopped|error","edge":..,"snapshotVersion":..,"stale":bool,"pq":true,"kex":"X25519MLKEM768"}
