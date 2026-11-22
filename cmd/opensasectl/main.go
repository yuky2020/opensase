// Command opensasectl is the OpenSASE admin CLI.
//
//	opensasectl [global flags] <command> [flags]
//
// Commands:
//
//	pki init         create a dev PKI directory (root CA, server certs, keys, edges.json)
//	pki export-ca    print the CA bundle published by the Control Plane
//	bootstrap        create a tenant, a user and a provisioning key; print the key
//	policy set       PUT the tenant policy from a JSON file
//	policy get       print the tenant policy
//	flows            list recent flow records of a tenant
//	devices          list devices of a tenant
//	revoke           revoke a device
//	edge add         register a Edge ID (its certificate is refused until then)
//	edge list        list registered edges
//	edge revoke      revoke an edge (permanent)
//	connector add    create a Connector; print its ID and one-time provisioning key
//	connector list   list Connectors of a tenant
//	connector revoke revoke a Connector (Edges drop it at the next peer sync)
//	app set          replace the tenant's private apps (ZTNA) from a JSON file
//	app list         list the tenant's private apps
//	categories       list the web categories (UT1) the Control Plane loaded
//	inspection-ca    download the tenant's web inspection root (ADR-0018)
//	oidc get         print tenant OIDC configuration
//	oidc set         configure OIDC sign-in for a tenant
//	oidc delete      remove tenant OIDC configuration
//	pq-check         TLS handshake check: prints the negotiated key exchange
//
// Global flags default to $OPENSASE_URL, $OPENSASE_CA and $OPENSASE_ADMIN_TOKEN. Secrets
// never need to be on the command line: the admin token comes from $OPENSASE_ADMIN_TOKEN
// or -token-file (a 0600 file); bootstrap and connector add print provisioning keys on stdout
// only (connector add can also write the key to a 0600 file with -key-out).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/pki"
	"github.com/yuky2020/opensase/pkg/pqsession"
)

type globals struct {
	url, ca, token string
	timeout        time.Duration
	expectEdge     string // pq-check: expect an edge identity instead of the Control Plane
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var g globals
	fs := flag.NewFlagSet("opensasectl", flag.ExitOnError)
	fs.StringVar(&g.url, "url", envOr("OPENSASE_URL", "https://localhost:9443"), "Control Plane URL ($OPENSASE_URL)")
	fs.StringVar(&g.ca, "ca", envOr("OPENSASE_CA", "deploy/dev/pki/root.crt"), "root CA PEM ($OPENSASE_CA)")
	fs.StringVar(&g.token, "token", "", "admin token; visible in ps, prefer $OPENSASE_ADMIN_TOKEN or -token-file")
	tokenFile := fs.String("token-file", "", "file holding the admin token (mode 0600)")
	fs.DurationVar(&g.timeout, "timeout", 15*time.Second, "request timeout")
	fs.Usage = usage(fs)
	_ = fs.Parse(os.Args[1:])
	if g.token != "" {
		fmt.Fprintln(os.Stderr, "opensasectl: warning: -token exposes the admin token in the process list; use $OPENSASE_ADMIN_TOKEN or -token-file")
	}
	if g.token == "" && *tokenFile != "" {
		t, err := readSecretFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "opensasectl:", err)
			os.Exit(1)
		}
		g.token = t
	}
	if g.token == "" {
		g.token = os.Getenv("OPENSASE_ADMIN_TOKEN")
	}
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	if err := dispatch(ctx, &g, args); err != nil {
		fmt.Fprintln(os.Stderr, "opensasectl:", err)
		os.Exit(1)
	}
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprint(os.Stderr, `usage: opensasectl [global flags] <command> [flags]

commands:
  pki init -dir DIR [-edge-id ID] [-session-url URL] [-wg-endpoint HOST:PORT] [-broker-addr HOST:PORT] [-region R]
  pki export-ca [-o FILE]
  bootstrap -tenant ID [-tenant-name N] -user-id ID -email E [-name N] [-max-uses N] [-valid-for DUR] [-control-url URL]
  policy set -tenant ID -f FILE
  policy get -tenant ID
  flows -tenant ID [-limit N] [-json]
  devices -tenant ID
  revoke -tenant ID -device ID
  edge add -id ID [-tenant T] | edge list | edge revoke -id ID
  connector add -tenant ID -name N [-group G] [-key-out FILE]
  connector list -tenant ID
  connector revoke -tenant ID -id C
  app set -tenant ID -file apps.json      ([]api.TenantPrivateApp; replaces privateApps)
  app list -tenant ID
  admin-token add -tenant ID -name N [-role admin|policy-editor|viewer] [-valid-for DUR] [-token-out FILE]
  admin-token list -tenant ID
  admin-token revoke -tenant ID -id ID
  whoami
  audit [-tenant ID] [-limit N] [-json]   (without -tenant: every tenant, super-admin only)
  audit verify [-id N -hash H]            (check the audit hash chain; with -id/-hash also a head published earlier)
  info                                    (pinned control URL for enrollment, version)
  dlp-dataset put -tenant ID -name N -kind values|document -file F [-file F2...]   (values: one per line; ADR-0029)
  dlp-dataset list -tenant ID | dlp-dataset delete -tenant ID -name N
  oidc get -tenant ID [-json]
  oidc set -tenant ID -issuer URL -client-id ID [-client-secret-file FILE] -group G=ROLE...
  oidc delete -tenant ID
  categories [-json]                      (web category list loaded by the Control Plane, ADR-0022)
  inspection-ca -tenant ID [-o FILE]      (web inspection root to install on devices, ADR-0018)
  pq-check [-edge-id ID]

global flags:
`)
		fs.PrintDefaults()
	}
}

func dispatch(ctx context.Context, g *globals, args []string) error {
	cmd, rest := args[0], args[1:]
	if (cmd == "pki" || cmd == "policy" || cmd == "edge" || cmd == "connector" || cmd == "app" || cmd == "admin-token") && len(rest) > 0 {
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	switch cmd {
	case "pki init":
		return pkiInit(rest)
	case "pki export-ca":
		return exportCA(ctx, g, rest)
	case "bootstrap":
		return bootstrap(ctx, g, rest)
	case "policy set":
		return policySet(ctx, g, rest)
	case "policy get":
		return policyGet(ctx, g, rest)
	case "flows":
		return flows(ctx, g, rest)
	case "devices":
		return devices(ctx, g, rest)
	case "revoke":
		return revoke(ctx, g, rest)
	case "edge add":
		return edgeAdd(ctx, g, rest)
	case "edge list":
		return edgeList(ctx, g)
	case "edge revoke":
		return edgeRevoke(ctx, g, rest)
	case "connector add":
		return connectorAdd(ctx, g, rest)
	case "connector list":
		return connectorList(ctx, g, rest)
	case "connector revoke":
		return connectorRevoke(ctx, g, rest)
	case "app set":
		return appSet(ctx, g, rest)
	case "app list":
		return appList(ctx, g, rest)
	case "admin-token add":
		return adminTokenAdd(ctx, g, rest)
	case "admin-token list":
		return adminTokenList(ctx, g, rest)
	case "admin-token revoke":
		return adminTokenRevoke(ctx, g, rest)
	case "whoami":
		return whoami(ctx, g)
	case "audit":
		if len(rest) > 0 && rest[0] == "verify" {
			return auditVerify(ctx, g, rest[1:])
		}
		return audit(ctx, g, rest)
	case "categories":
		return listCategories(ctx, g, rest)
	case "dlp-dataset":
		return dlpDataset(ctx, g, rest)
	case "oidc":
		return oidcCmd(ctx, g, rest)
	case "info":
		var info api.AdminInfo
		if err := g.do(ctx, http.MethodGet, "/v1/admin/info", nil, &info); err != nil {
			return err
		}
		fmt.Printf("control URL  %s\nroot sha256  %s\nversion      %s\nfeatures     %s\n", info.ControlURL, info.RootSHA256, info.Version, strings.Join(info.Features, ", "))
		return nil
	case "inspection-ca":
		return inspectionCA(ctx, g, rest)
	case "pq-check":
		return pqCheck(ctx, g, rest)
	}
	return fmt.Errorf("unknown command %q (run without arguments for help)", cmd)
}

// --- HTTP client ---

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.msg) }

func (g *globals) tlsConfig() (*tls.Config, error) {
	pem, err := os.ReadFile(g.ca)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", g.ca, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate in %s", g.ca)
	}
	cfg := pqsession.Harden(&tls.Config{RootCAs: pool})
	// The server must prove the Control Plane identity (SPIFFE URI), not just a host name.
	cfg.VerifyConnection = pki.ExpectServer(pki.ServerControlPlane, "")
	if g.expectEdge != "" {
		cfg.VerifyConnection = pki.ExpectServer(pki.ServerEdge, g.expectEdge)
	}
	return cfg, nil
}

// readSecretFile reads a secret from a file that must not be readable by group or others.
func readSecretFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must not be accessible by group or others (chmod 600)", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: secret file path is an operator-supplied flag
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (g *globals) do(ctx context.Context, method, path string, in, out any) error {
	cfg, err := g.tlsConfig()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.url, "/")+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(path, "/v1/admin/") {
		if g.token == "" {
			return errors.New("admin token required (-token or $OPENSASE_ADMIN_TOKEN)")
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &apiError{resp.StatusCode, msg}
	}
	if b, ok := out.(*[]byte); ok { // non-JSON body (PEM download)
		*b = raw
		return nil
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// rootPin returns the hex SHA-256 of the first certificate (the provider root) in the CA file.
func (g *globals) rootPin() (string, error) {
	b, err := os.ReadFile(g.ca)
	if err != nil {
		return "", fmt.Errorf("read CA %s: %w", g.ca, err)
	}
	certs, err := pki.ParseCertsPEM(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func isStatus(err error, code int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.status == code
}

// --- commands ---

func pkiInit(args []string) error {
	fs := flag.NewFlagSet("pki init", flag.ExitOnError)
	dir := fs.String("dir", "deploy/dev/pki", "PKI directory (Edge material goes to DIR/edge)")
	edgeID := fs.String("edge-id", "edge-1", "edge ID")
	sessionURL := fs.String("session-url", "https://edge:8443", "edge session URL given to devices")
	wgEndpoint := fs.String("wg-endpoint", "edge:51820", "edge WireGuard endpoint given to devices")
	brokerAddr := fs.String("broker-addr", "edge:8444", "edge broker address Connectors dial (empty: none)")
	region := fs.String("region", "dev", "edge region")
	cpSAN := fs.String("cp-san", sanList(pki.KindControlPlane), "comma-separated DNS names / IPs of the Control Plane certificate")
	edgeSAN := fs.String("edge-san", sanList(pki.KindEdge), "comma-separated DNS names / IPs of the Edge certificate")
	_ = fs.Parse(args)

	cpDNS, cpIPs := pki.ParseSANs(*cpSAN)
	edDNS, edIPs := pki.ParseSANs(*edgeSAN)
	if err := pki.InitDir(*dir, pki.InitOptions{
		EdgeID:   *edgeID,
		CPSANs:   pki.ServerCertOptions{DNSNames: cpDNS, IPs: cpIPs},
		EdgeSANs: pki.ServerCertOptions{DNSNames: edDNS, IPs: edIPs},
	}); err != nil {
		return err
	}
	_, pub, err := pki.LoadWireGuardKey(filepath.Join(*dir, pki.EdgeDir, pki.EdgeWGKeyFile))
	if err != nil {
		return err
	}
	edges := []api.EdgeInfo{{ID: *edgeID, Region: *region, SessionURL: *sessionURL, WGEndpoint: *wgEndpoint, WGPublicKey: encodeB64(pub), BrokerAddr: *brokerAddr}}
	b, _ := json.MarshalIndent(edges, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "edges.json"), append(b, '\n'), 0o644); err != nil { //nolint:gosec // G306: edges.json holds only public edge metadata (IDs, URLs, public keys)
		return err
	}
	fmt.Fprintf(os.Stderr, "PKI ready in %s (edge %s at %s)\n", *dir, *edgeID, *sessionURL)
	return nil
}

// sanList returns the dev default SANs of a server kind as a flag default.
func sanList(k pki.ServerKind) string {
	dns, ips := pki.DevServerSANs(k)
	out := append([]string(nil), dns...)
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return strings.Join(out, ",")
}

func exportCA(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("pki export-ca", flag.ExitOnError)
	out := fs.String("o", "", "write to file instead of stdout")
	_ = fs.Parse(args)
	var b api.PKIBundle
	if err := g.do(ctx, http.MethodGet, "/v1/pki/ca", nil, &b); err != nil {
		return err
	}
	if *out != "" {
		return os.WriteFile(*out, []byte(b.CAPEM), 0o644) //nolint:gosec // G306: CA certificate is public
	}
	_, err := io.WriteString(os.Stdout, b.CAPEM)
	return err
}

func bootstrap(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	tenant := fs.String("tenant", "acme", "tenant ID")
	tenantName := fs.String("tenant-name", "", "tenant name (default: the ID)")
	userID := fs.String("user-id", "user-1", "user ID")
	email := fs.String("email", "user@example.com", "user email")
	name := fs.String("name", "Dev User", "user name")
	maxUses := fs.Int("max-uses", 5, "provisioning key uses")
	validFor := fs.Duration("valid-for", 24*time.Hour, "provisioning key validity")
	public := fs.String("control-url", "", "Control Plane URL as devices reach it (default: -url)")
	edgeID := fs.String("edge-id", "edge-1", "edge ID to register (empty: none)")
	_ = fs.Parse(args)
	if *public == "" {
		*public = g.url
	}
	pin, err := g.rootPin()
	if err != nil {
		return err
	}
	if *tenantName == "" {
		*tenantName = *tenant
	}
	err = g.do(ctx, http.MethodPost, "/v1/admin/tenants", api.AdminTenant{ID: *tenant, Name: *tenantName}, nil)
	switch {
	case err == nil:
		fmt.Fprintf(os.Stderr, "tenant %s created\n", *tenant)
	case isStatus(err, http.StatusConflict):
		fmt.Fprintf(os.Stderr, "tenant %s exists\n", *tenant)
	default:
		return fmt.Errorf("create tenant: %w", err)
	}
	err = g.do(ctx, http.MethodPost, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/users", api.AdminUser{ID: *userID, Email: *email, Name: *name}, nil)
	switch {
	case err == nil:
		fmt.Fprintf(os.Stderr, "user %s created\n", *userID)
	case isStatus(err, http.StatusConflict):
		fmt.Fprintf(os.Stderr, "user %s exists\n", *userID)
	default:
		return fmt.Errorf("create user: %w", err)
	}
	if *edgeID != "" {
		if err := registerEdge(ctx, g, *edgeID, ""); err != nil {
			return err
		}
	}
	var k api.ProvisioningKey
	if err := g.do(ctx, http.MethodPost, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/provisioning-keys",
		api.ProvisioningKeyRequest{UserID: *userID, MaxUses: *maxUses, ValidFor: int(validFor.Seconds())}, &k); err != nil {
		return fmt.Errorf("create provisioning key: %w", err)
	}
	pinned := strings.TrimRight(strings.SplitN(*public, "#", 2)[0], "/") + "#sha256=" + pin
	// PROPOSAL (QR payload, not yet in pkg/api): opensase://enroll?control=<pinned URL>&key=<key>
	enrollURI := "opensase://enroll?" + url.Values{"control": {pinned}, "key": {k.Key}}.Encode()
	fmt.Fprintf(os.Stderr, "provisioning key for %s (max %d uses, expires %s)\n", *userID, *maxUses, k.ExpiresAt.Format(time.RFC3339))
	// stdout is KEY=VALUE lines so scripts can parse them.
	fmt.Printf("CONTROL_URL=%s\nPROVISIONING_KEY=%s\nENROLL_URI=%s\n", pinned, k.Key, enrollURI)
	return nil
}

func tenantFlag(fs *flag.FlagSet) *string {
	return fs.String("tenant", envOr("OPENSASE_TENANT", "acme"), "tenant ID ($OPENSASE_TENANT)")
}

func policySet(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("policy set", flag.ExitOnError)
	tenant := tenantFlag(fs)
	file := fs.String("f", "", "policy JSON file (api.TenantPolicy)")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var tp api.TenantPolicy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tp); err != nil {
		return fmt.Errorf("parse %s: %w", *file, err)
	}
	if err := g.do(ctx, http.MethodPut, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/policy", tp, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "policy applied to tenant %s (%d rules); device snapshots recompiled\n", *tenant, len(tp.Rules))
	return nil
}

func policyGet(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("policy get", flag.ExitOnError)
	tenant := tenantFlag(fs)
	_ = fs.Parse(args)
	var tp api.TenantPolicy
	if err := g.do(ctx, http.MethodGet, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/policy", nil, &tp); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(tp)
}

func flows(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("flows", flag.ExitOnError)
	tenant := tenantFlag(fs)
	limit := fs.Int("limit", 50, "number of records")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	var b api.FlowBatch
	if err := g.do(ctx, http.MethodGet, fmt.Sprintf("/v1/admin/tenants/%s/flows?limit=%d", url.PathEscape(*tenant), *limit), nil, &b); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "START\tWHERE\tDEVICE\tPROTO\tDESTINATION\tDOMAIN\tACTION\tLAYER\tRULE\tOUT\tIN")
	for _, r := range b.Records {
		dev := r.DeviceID
		if len(dev) > 8 {
			dev = dev[:8]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			r.Start.Local().Format("15:04:05"), r.Where, dev, r.Flow.Protocol,
			net.JoinHostPort(r.Flow.DstIP, fmt.Sprint(r.Flow.DstPort)), dash(r.Flow.Domain),
			r.Decision.Action, r.Decision.Layer, dash(r.Decision.RuleID), r.BytesOut, r.BytesIn)
	}
	return tw.Flush()
}

func devices(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	tenant := tenantFlag(fs)
	_ = fs.Parse(args)
	var ds []struct {
		ID, UserID, Name, Platform string
		Revoked                    bool
		CreatedAt                  time.Time
	}
	if err := g.do(ctx, http.MethodGet, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/devices", nil, &ds); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSER\tNAME\tPLATFORM\tREVOKED\tCREATED")
	for _, d := range ds {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\n", d.ID, d.UserID, d.Name, d.Platform, d.Revoked, d.CreatedAt.Local().Format(time.DateTime))
	}
	return tw.Flush()
}

func revoke(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	tenant := tenantFlag(fs)
	dev := fs.String("device", "", "device ID")
	_ = fs.Parse(args)
	if *dev == "" {
		return errors.New("-device is required")
	}
	return g.do(ctx, http.MethodPost, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/devices/"+url.PathEscape(*dev)+"/revoke", nil, nil)
}

// pqCheck performs a handshake with the hardened config and reports the key exchange.
// Servers that require a client certificate (the Edge) still report the curve, because
// in TLS 1.3 the client finishes its handshake before the server checks the certificate.
func pqCheck(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("pq-check", flag.ExitOnError)
	fs.StringVar(&g.expectEdge, "edge-id", "", "expect the Edge with this ID instead of the Control Plane")
	_ = fs.Parse(args)
	cfg, err := g.tlsConfig()
	if err != nil {
		return err
	}
	u, err := url.Parse(g.url)
	if err != nil || u.Host == "" {
		return fmt.Errorf("bad URL %q", g.url)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	cfg.ServerName = u.Hostname()
	d := &tls.Dialer{Config: cfg}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", host, err)
	}
	defer c.Close()
	cs := c.(*tls.Conn).ConnectionState()
	if err := pqsession.CheckPostQuantum(cs); err != nil {
		return err
	}
	fmt.Printf("%s: TLS 1.3, key exchange %s, cipher %s, server %s\n", host, cs.CurveID, tls.CipherSuiteName(cs.CipherSuite), cs.PeerCertificates[0].Subject.CommonName)
	return nil
}

type adminEdge = api.AdminEdge

// registerEdge registers an edge; tenantID != "" makes it a Private Edge of that tenant (ADR-0014).
func registerEdge(ctx context.Context, g *globals, id, tenantID string) error {
	err := g.do(ctx, http.MethodPost, "/v1/admin/edges", adminEdge{ID: id, TenantID: tenantID}, nil)
	switch {
	case err == nil:
		fmt.Fprintf(os.Stderr, "edge %s registered\n", id)
	case isStatus(err, http.StatusConflict):
		fmt.Fprintf(os.Stderr, "edge %s already registered\n", id)
	default:
		return fmt.Errorf("register edge: %w", err)
	}
	return nil
}

func edgeAdd(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("edge add", flag.ExitOnError)
	id := fs.String("id", "", "edge ID (as in its certificate, spiffe://opensase/edge/<id>)")
	tenant := fs.String("tenant", "", "bind the edge to this tenant: a Private Edge (ADR-0014); empty = public multi-tenant edge")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	return registerEdge(ctx, g, *id, *tenant)
}

func edgeList(ctx context.Context, g *globals) error {
	var es []adminEdge
	if err := g.do(ctx, http.MethodGet, "/v1/admin/edges", nil, &es); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTENANT\tREVOKED\tCREATED")
	for _, e := range es {
		tenant := e.TenantID
		if tenant == "" {
			tenant = "(public)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n", e.ID, tenant, e.Revoked, e.CreatedAt.Local().Format(time.DateTime))
	}
	return tw.Flush()
}

func edgeRevoke(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("edge revoke", flag.ExitOnError)
	id := fs.String("id", "", "edge ID")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	return g.do(ctx, http.MethodPost, "/v1/admin/edges/"+url.PathEscape(*id)+"/revoke", nil, nil)
}

// --- Tenant admin tokens (ST-03) ---

func adminTokensPath(tenant string) string {
	return "/v1/admin/tenants/" + url.PathEscape(tenant) + "/admin-tokens"
}

func adminTokenAdd(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("admin-token add", flag.ExitOnError)
	tenant := tenantFlag(fs)
	name := fs.String("name", "", "token name (who or what uses it)")
	validFor := fs.Duration("valid-for", 0, "validity (default 90 days, at most 365)")
	role := fs.String("role", "admin", "admin | policy-editor | viewer (ADR-0027)")
	out := fs.String("token-out", "", "write the token to this file (mode 0600, must not exist) instead of stdout")
	_ = fs.Parse(args)
	if *name == "" {
		return errors.New("-name is required")
	}
	var c api.AdminTokenCreated
	if err := g.do(ctx, http.MethodPost, adminTokensPath(*tenant), api.AdminTokenRequest{Name: *name, ValidFor: int(validFor.Seconds()), Role: *role}, &c); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "admin token %s (%s) for tenant %s, valid until %s; it is shown only once\n",
		c.ID, c.Name, c.TenantID, c.ExpiresAt.Local().Format(time.DateTime))
	if *out != "" {
		if err := writeNewSecret(*out, c.Token); err != nil {
			return fmt.Errorf("admin token %s created, but writing it failed (revoke it and retry): %w", c.ID, err)
		}
		fmt.Fprintf(os.Stderr, "token written to %s\n", *out)
		fmt.Printf("ADMIN_TOKEN_ID=%s\n", c.ID)
		return nil
	}
	fmt.Printf("ADMIN_TOKEN_ID=%s\nADMIN_TOKEN=%s\n", c.ID, c.Token)
	return nil
}

func adminTokenList(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("admin-token list", flag.ExitOnError)
	tenant := tenantFlag(fs)
	_ = fs.Parse(args)
	var ts []api.AdminToken
	if err := g.do(ctx, http.MethodGet, adminTokensPath(*tenant), nil, &ts); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tROLE\tREVOKED\tCREATED\tEXPIRES\tLAST USED")
	for _, t := range ts {
		used := "-"
		if !t.LastUsed.IsZero() {
			used = t.LastUsed.Local().Format(time.DateTime)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\t%s\n", t.ID, t.Name, t.Role, t.Revoked, t.CreatedAt.Local().Format(time.DateTime), t.ExpiresAt.Local().Format(time.DateTime), used)
	}
	return tw.Flush()
}

func adminTokenRevoke(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("admin-token revoke", flag.ExitOnError)
	tenant := tenantFlag(fs)
	id := fs.String("id", "", "admin token ID")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	if err := g.do(ctx, http.MethodPost, adminTokensPath(*tenant)+"/"+url.PathEscape(*id)+"/revoke", nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "admin token %s revoked\n", *id)
	return nil
}

func whoami(ctx context.Context, g *globals) error {
	var id api.AdminIdentity
	if err := g.do(ctx, http.MethodGet, "/v1/admin/whoami", nil, &id); err != nil {
		return err
	}
	if id.Role == "super" {
		fmt.Println("super-admin (all tenants, Edge registry)")
		return nil
	}
	fmt.Printf("tenant %s of %s (token %s)\n", id.TenantRole, id.TenantID, id.TokenID)
	return nil
}

func audit(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant ID (default: every tenant, super-admin only)")
	limit := fs.Int("limit", 100, "maximum entries (at most 1000)")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	path := "/v1/admin/audit"
	if *tenant != "" {
		path = "/v1/admin/tenants/" + url.PathEscape(*tenant) + "/audit"
	}
	var es []api.AuditEntry
	if err := g.do(ctx, http.MethodGet, path+"?limit="+strconv.Itoa(*limit), nil, &es); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(es)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTOR\tTENANT\tMETHOD\tPATH\tSTATUS")
	for _, e := range es {
		tn := e.TenantID
		if tn == "" {
			tn = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", e.At.Local().Format(time.DateTime), e.Actor, tn, e.Method, e.Path, e.Status)
	}
	return tw.Flush()
}

// writeNewSecret writes v to a new file with mode 0600; it refuses to overwrite.
func writeNewSecret(path, v string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen output path, created exclusively
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintln(f, v)
	return errors.Join(werr, f.Close())
}

// --- Connectors and private apps (ADR-0013) ---

func connectorsPath(tenant string) string {
	return "/v1/admin/tenants/" + url.PathEscape(tenant) + "/connectors"
}

func connectorAdd(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("connector add", flag.ExitOnError)
	tenant := tenantFlag(fs)
	name := fs.String("name", "", "connector name")
	group := fs.String("group", "", "connector group (default \"default\")")
	keyOut := fs.String("key-out", "", "also write the provisioning key to this file (mode 0600, must not exist)")
	_ = fs.Parse(args)
	if *name == "" {
		return errors.New("-name is required")
	}
	var c api.AdminConnectorCreated
	if err := g.do(ctx, http.MethodPost, connectorsPath(*tenant), api.AdminConnectorRequest{Name: *name, Group: *group}, &c); err != nil {
		return err
	}
	if *keyOut != "" {
		f, err := os.OpenFile(*keyOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("connector %s created, but writing the key failed (revoke it and retry): %w", c.Connector.ID, err)
		}
		_, werr := fmt.Fprintln(f, c.ProvisioningKey)
		if err := errors.Join(werr, f.Close()); err != nil {
			return fmt.Errorf("connector %s created, but writing the key failed (revoke it and retry): %w", c.Connector.ID, err)
		}
		fmt.Fprintf(os.Stderr, "provisioning key written to %s\n", *keyOut)
	}
	fmt.Fprintf(os.Stderr, "connector %s (%s) created in group %s; the provisioning key is single use, valid 24h, and shown only once\n",
		c.Connector.ID, c.Connector.Name, c.Connector.Group)
	// stdout is KEY=VALUE lines so scripts can parse them.
	fmt.Printf("CONNECTOR_ID=%s\nPROVISIONING_KEY=%s\n", c.Connector.ID, c.ProvisioningKey)
	return nil
}

func connectorList(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("connector list", flag.ExitOnError)
	tenant := tenantFlag(fs)
	_ = fs.Parse(args)
	var cs []api.AdminConnector
	if err := g.do(ctx, http.MethodGet, connectorsPath(*tenant), nil, &cs); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tGROUP\tREVOKED\tCREATED\tLAST SEEN")
	for _, c := range cs {
		seen := "-"
		if !c.LastSeen.IsZero() {
			seen = c.LastSeen.Local().Format(time.DateTime)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\n", c.ID, c.Name, c.Group, c.Revoked, c.CreatedAt.Local().Format(time.DateTime), seen)
	}
	return tw.Flush()
}

func connectorRevoke(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("connector revoke", flag.ExitOnError)
	tenant := tenantFlag(fs)
	id := fs.String("id", "", "connector ID")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	if err := g.do(ctx, http.MethodPost, connectorsPath(*tenant)+"/"+url.PathEscape(*id)+"/revoke", nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "connector %s revoked\n", *id)
	return nil
}

func policyPath(tenant string) string {
	return "/v1/admin/tenants/" + url.PathEscape(tenant) + "/policy"
}

// appSet replaces TenantPolicy.PrivateApps (read-modify-write of the tenant policy).
func appSet(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("app set", flag.ExitOnError)
	tenant := tenantFlag(fs)
	file := fs.String("file", "", "JSON file with []api.TenantPrivateApp")
	_ = fs.Parse(args)
	if *file == "" {
		return errors.New("-file is required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var apps []api.TenantPrivateApp
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&apps); err != nil {
		return fmt.Errorf("parse %s: %w", *file, err)
	}
	var tp api.TenantPolicy
	if err := g.do(ctx, http.MethodGet, policyPath(*tenant), nil, &tp); err != nil {
		return err
	}
	tp.PrivateApps = apps
	if err := g.do(ctx, http.MethodPut, policyPath(*tenant), tp, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d private apps set for tenant %s; device snapshots and connector configs updated\n", len(apps), *tenant)
	return nil
}

func appList(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("app list", flag.ExitOnError)
	tenant := tenantFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON ([]api.TenantPrivateApp, accepted by app set)")
	_ = fs.Parse(args)
	var tp api.TenantPolicy
	if err := g.do(ctx, http.MethodGet, policyPath(*tenant), nil, &tp); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if tp.PrivateApps == nil {
			tp.PrivateApps = []api.TenantPrivateApp{}
		}
		return enc.Encode(tp.PrivateApps)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tGROUP\tDOMAINS\tPORTS\tUSERS")
	for _, a := range tp.PrivateApps {
		ports := make([]string, 0, len(a.Ports))
		for _, p := range a.Ports {
			if p.To != 0 && p.To != p.From {
				ports = append(ports, fmt.Sprintf("%d-%d", p.From, p.To))
			} else {
				ports = append(ports, fmt.Sprint(p.From))
			}
		}
		users := "all"
		if len(a.Users) > 0 {
			users = strings.Join(a.Users, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, dash(a.Name), a.ConnectorGroup, strings.Join(a.Domains, ","), strings.Join(ports, ","), users)
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// inspectionCA downloads the tenant's web inspection root (ADR-0018), the certificate the
// tenant's devices must trust for TLS inspection.
func inspectionCA(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("inspection-ca", flag.ExitOnError)
	tenant := tenantFlag(fs)
	out := fs.String("o", "", "write the PEM to FILE (default stdout)")
	_ = fs.Parse(args)
	var pemBytes []byte
	if err := g.do(ctx, http.MethodGet, "/v1/admin/tenants/"+url.PathEscape(*tenant)+"/inspection-ca", nil, &pemBytes); err != nil {
		return err
	}
	if _, err := pki.ParseCertsPEM(pemBytes); err != nil {
		return fmt.Errorf("inspection root: %w", err)
	}
	if *out == "" {
		_, err := os.Stdout.Write(pemBytes)
		return err
	}
	return os.WriteFile(*out, pemBytes, 0o644) //nolint:gosec // G306: a public CA certificate
}

// listCategories prints the web category list the Control Plane loaded (ADR-0022).
func listCategories(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("categories", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	var cat api.CategoryCatalog
	if err := g.do(ctx, http.MethodGet, "/v1/admin/categories", nil, &cat); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cat)
	}
	if cat.Version == "" {
		fmt.Println("no category list loaded (controlplane -categories-file / -categories-url)")
		return nil
	}
	fmt.Printf("%s (%s), version %s, loaded %s\n", cat.Source, cat.Licence, cat.Version, cat.LoadedAt.Local().Format(time.DateTime))
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tDOMAINS\tTITLE")
	for _, c := range cat.Categories {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", c.Name, c.Type, c.Domains, c.Title)
	}
	return tw.Flush()
}

// auditVerify checks the admin audit hash chain (ADR-0028). It exits non-zero when the chain
// is broken or a pinned head does not match.
func auditVerify(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	id := fs.Int64("id", 0, "entry ID of a head hash published earlier")
	hash := fs.String("hash", "", "the hash published for -id")
	_ = fs.Parse(args)
	path := "/v1/admin/audit/verify"
	if *id > 0 && *hash != "" {
		path += fmt.Sprintf("?id=%d&hash=%s", *id, url.QueryEscape(*hash))
	}
	var v api.AuditVerification
	if err := g.do(ctx, http.MethodGet, path, nil, &v); err != nil {
		return err
	}
	fmt.Printf("entries %d, head entry %d, head %s\n", v.Entries, v.HeadID, v.Head)
	if v.AnchorID > 0 {
		fmt.Printf("entries up to %d removed by retention (anchored)\n", v.AnchorID)
	}
	if v.Pinned != "" {
		fmt.Printf("published head of entry %d: %s\n", *id, v.Pinned)
	}
	if v.BadID != 0 {
		return fmt.Errorf("audit chain broken at entry %d: %s", v.BadID, v.Reason)
	}
	if !v.OK {
		return errors.New("audit history does not match the published head")
	}
	fmt.Println("audit chain OK")
	return nil
}

type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

// dlpDataset manages DLP datasets (ADR-0029). Values and documents are read locally and sent
// once; the Control Plane keeps only keyed hashes.
func dlpDataset(ctx context.Context, g *globals, args []string) error {
	if len(args) == 0 {
		return errors.New("dlp-dataset put|list|delete")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("dlp-dataset "+sub, flag.ExitOnError)
	tenant := tenantFlag(fs)
	name := fs.String("name", "", "dataset name")
	kind := fs.String("kind", "values", "values | document")
	var files fileList
	fs.Var(&files, "file", "values file (one per line) or document (repeatable)")
	_ = fs.Parse(args)
	base := "/v1/admin/tenants/" + url.PathEscape(*tenant) + "/dlp-datasets"
	switch sub {
	case "list":
		var ds []api.DLPDataset
		if err := g.do(ctx, http.MethodGet, base, nil, &ds); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tKIND\tENTRIES\tUPDATED")
		for _, d := range ds {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", d.Name, d.Kind, d.Entries, d.UpdatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	case "delete":
		return g.do(ctx, http.MethodDelete, base+"/"+url.PathEscape(*name), nil, nil)
	case "put":
		if *name == "" || len(files) == 0 {
			return errors.New("-name and at least one -file are required")
		}
		req := api.DLPDatasetRequest{Kind: *kind}
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: files named by the operator
			if err != nil {
				return err
			}
			if *kind == "values" {
				for _, line := range strings.Split(string(b), "\n") {
					if line = strings.TrimSpace(line); line != "" {
						req.Values = append(req.Values, line)
					}
				}
			} else {
				req.Documents = append(req.Documents, b)
			}
		}
		var d api.DLPDataset
		if err := g.do(ctx, http.MethodPut, base+"/"+url.PathEscape(*name), req, &d); err != nil {
			return err
		}
		fmt.Printf("dataset %s (%s): %d entries\n", d.Name, d.Kind, d.Entries)
		return nil
	}
	return fmt.Errorf("unknown dlp-dataset command %q", sub)
}

// oidcCmd manages tenant OpenID Connect configuration (issue #17, slice B, ADR-0031).
func oidcCmd(ctx context.Context, g *globals, args []string) error {
	if len(args) == 0 {
		return errors.New("oidc get|set|delete")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("oidc "+sub, flag.ExitOnError)
	tenant := tenantFlag(fs)
	switch sub {
	case "get":
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(args)
		var o api.TenantOIDC
		path := "/v1/admin/tenants/" + url.PathEscape(*tenant) + "/oidc"
		if err := g.do(ctx, http.MethodGet, path, nil, &o); err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(o) //nolint:gosec // G117: the server never returns the secret (HasSecret only), so the field is empty
		}
		fmt.Printf("issuer       %s\n", o.Issuer)
		fmt.Printf("client ID    %s\n", o.ClientID)
		fmt.Printf("has secret   %t\n", o.HasSecret)
		fmt.Println("group roles:")
		grps := make([]string, 0, len(o.GroupRoles))
		for grp := range o.GroupRoles {
			grps = append(grps, grp)
		}
		sort.Strings(grps)
		for _, grp := range grps {
			fmt.Printf("  %s -> %s\n", grp, o.GroupRoles[grp])
		}
		fmt.Printf("redirect URL %s\n", o.RedirectURL)
		return nil

	case "set":
		issuer := fs.String("issuer", "", "identity provider issuer URL (https)")
		clientID := fs.String("client-id", "", "client ID")
		clientSecretFile := fs.String("client-secret-file", "", "file containing client secret (mode 0600)")
		var groups fileList
		fs.Var(&groups, "group", "group to role mapping in GROUP=ROLE format (repeatable)")
		_ = fs.Parse(args)

		if *issuer == "" || *clientID == "" {
			return errors.New("-issuer, -client-id, and at least one -group G=ROLE are required")
		}

		groupRoles, err := parseGroupRoles(groups)
		if err != nil {
			return err
		}

		var secret string
		if *clientSecretFile != "" {
			s, err := readSecretFile(*clientSecretFile)
			if err != nil {
				return err
			}
			secret = s
		}

		req := api.TenantOIDC{
			Issuer:       *issuer,
			ClientID:     *clientID,
			ClientSecret: secret,
			GroupRoles:   groupRoles,
		}
		var out api.TenantOIDC
		path := "/v1/admin/tenants/" + url.PathEscape(*tenant) + "/oidc"
		if err := g.do(ctx, http.MethodPut, path, req, &out); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "OIDC configured for tenant %s\n", *tenant)
		fmt.Printf("redirect URL: %s\n", out.RedirectURL)
		return nil

	case "delete":
		_ = fs.Parse(args)
		path := "/v1/admin/tenants/" + url.PathEscape(*tenant) + "/oidc"
		if err := g.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "OIDC removed for tenant %s\n", *tenant)
		return nil
	}
	return fmt.Errorf("unknown oidc command %q", sub)
}

func parseGroupRoles(groups []string) (map[string]string, error) {
	if len(groups) == 0 {
		return nil, errors.New("at least one -group G=ROLE is required")
	}
	groupRoles := make(map[string]string, len(groups))
	for _, item := range groups {
		idx := strings.LastIndex(item, "=")
		if idx <= 0 || idx == len(item)-1 {
			return nil, fmt.Errorf("invalid -group format %q: expected GROUP=ROLE", item)
		}
		role := item[idx+1:]
		if role != api.TenantRoleAdmin && role != api.TenantRolePolicyEditor && role != api.TenantRoleViewer {
			return nil, fmt.Errorf("invalid role %q: must be admin, policy-editor, or viewer", role)
		}
		groupRoles[item[:idx]] = role
	}
	return groupRoles, nil
}
