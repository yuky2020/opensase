//go:build windows

// Command opensased is the OpenSASE desktop daemon (issue #31).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/yuky2020/opensase/internal/clientnet"
	"github.com/yuky2020/opensase/internal/desktop"
)

const (
	serviceName        = "OpenSASE"
	serviceDisplayName = "OpenSASE client"
	serviceDesc        = "OpenSASE desktop daemon managing VPN tunnel and local API"
	defaultPipePath    = `\\.\pipe\opensase`
	pipeSDDL           = `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`
)

func defaultStateDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "OpenSASE")
}

func ensureSecureStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	return restrictPath(dir)
}

func restrictPath(path string) error {
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return fmt.Errorf("string to sid system: %w", err)
	}
	adminSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return fmt.Errorf("string to sid admin: %w", err)
	}

	sids := []*windows.SID{systemSID, adminSID}
	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for i, sid := range sids {
		entries[i] = windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("acl from entries: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

type eventLogHandler struct {
	elog   *eventlog.Log
	stderr slog.Handler
}

func (h *eventLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.stderr.Enabled(ctx, level)
}

func (h *eventLogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.stderr.Handle(ctx, r)
	if h.elog != nil {
		msg := r.Message
		if r.NumAttrs() > 0 {
			var b strings.Builder
			b.WriteString(msg)
			r.Attrs(func(a slog.Attr) bool {
				b.WriteString(" ")
				b.WriteString(a.Key)
				b.WriteString("=")
				fmt.Fprint(&b, a.Value.Any())
				return true
			})
			msg = b.String()
		}
		if r.Level >= slog.LevelError {
			_ = h.elog.Error(1, msg)
		} else if r.Level >= slog.LevelInfo {
			_ = h.elog.Info(1, msg)
		}
	}
	return nil
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{
		elog:   h.elog,
		stderr: h.stderr.WithAttrs(attrs),
	}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{
		elog:   h.elog,
		stderr: h.stderr.WithGroup(name),
	}
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("abs executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(serviceName)
	if err == nil {
		_ = s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  serviceDisplayName,
		Description:  serviceDesc,
		// The WFP filters of the kill switch match the daemon by its service SID (issue #38 research).
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}

	s, err = m.CreateService(serviceName, exePath, cfg, "run")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Recovery actions: restart after 5 s up to 3 times
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}
	if err := s.SetRecoveryActions(recoveryActions, 86400); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}

	// Install event log source
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Error); err != nil {
		fmt.Printf("warning: register event log source: %v\n", err)
	}

	fmt.Println("OpenSASE service installed successfully.")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer func() { _ = s.Close() }()

	if _, err := s.Control(svc.Stop); err == nil {
		time.Sleep(1 * time.Second)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	_ = eventlog.Remove(serviceName)
	fmt.Println("OpenSASE service uninstalled successfully.")
	return nil
}

type openSASEService struct {
	cancel context.CancelFunc
	done   <-chan struct{}
	log    *slog.Logger
}

func (s *openSASEService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.log.Info("OpenSASE service running")

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s.log.Info("OpenSASE service stopping", "cmd", req.Cmd)
			changes <- svc.Status{State: svc.StopPending}

			s.cancel()

			select {
			case <-s.done:
			case <-time.After(20 * time.Second):
				s.log.Warn("OpenSASE service stop timed out after 20s")
			}

			changes <- svc.Status{State: svc.Stopped}
			return
		default:
			s.log.Warn("unexpected service control request", "cmd", req.Cmd)
		}
	}
	return
}

func runDaemon(stateDir, pipePath, tunName, controlURL string, connectOnStart, verbose bool) error {
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	baseHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})

	elog, err := eventlog.Open(serviceName)
	var log *slog.Logger
	if err == nil {
		log = slog.New(&eventLogHandler{elog: elog, stderr: baseHandler})
		defer func() { _ = elog.Close() }()
	} else {
		log = slog.New(baseHandler)
	}
	slog.SetDefault(log)

	if err := ensureSecureStateDir(stateDir); err != nil {
		log.Error("secure state directory failed", "dir", stateDir, "err", err)
		return err
	}

	pipeConfig := &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		MessageMode:        false,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}
	ln, err := winio.ListenPipe(pipePath, pipeConfig)
	if err != nil {
		log.Error("listen on named pipe failed", "pipe", pipePath, "err", err)
		return err
	}
	defer ln.Close()

	d, err := desktop.NewDaemon(desktop.Config{
		StateDir:   stateDir,
		TUNName:    tunName,
		ControlURL: controlURL,
		Logger:     log,
	})
	if err != nil {
		log.Error("initialize daemon failed", "err", err)
		return err
	}

	if connectOnStart && d.Engine().IsEnrolled() {
		log.Info("connect-on-start: device is enrolled, connecting tunnel")
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if err := d.Connect(ctx); err != nil {
				log.Error("connect-on-start failed", "err", err)
			}
		}()
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Warn("check windows service status failed, assuming console", "err", err)
		isService = false
	}

	if isService {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})

		go func() {
			defer close(done)
			if err := d.Serve(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("daemon server terminated with error", "err", err)
			}
			_ = d.Disconnect()
		}()

		ensureServiceSID(log)

		svcHandler := &openSASEService{
			cancel: cancel,
			done:   done,
			log:    log,
		}
		if err := svc.Run(serviceName, svcHandler); err != nil {
			log.Error("svc.Run failed", "err", err)
			return err
		}
		return nil
	}

	// Foreground console debugging mode
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("opensased running in foreground", "pipe", pipePath, "tun", tunName)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- d.Serve(ctx, ln)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down opensased")
		_ = d.Disconnect()
	case err := <-serveErr:
		if err != nil {
			log.Error("daemon server terminated with error", "err", err)
			_ = d.Disconnect()
			return err
		}
	}
	return nil
}

func parseFlagsAndRun(args []string) error {
	var subcmd string
	var subcmdIdx = -1

	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			if arg == "install" || arg == "uninstall" || arg == "run" {
				subcmd = arg
				subcmdIdx = i
				break
			}
		}
	}

	if subcmd == "install" {
		return installService()
	}
	if subcmd == "uninstall" {
		return uninstallService()
	}

	var flagArgs []string
	if subcmdIdx >= 0 {
		flagArgs = append(flagArgs, args[:subcmdIdx]...)
		flagArgs = append(flagArgs, args[subcmdIdx+1:]...)
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("opensased", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory (keys, certificate, cached snapshot)")
	pipePath := fs.String("pipe", defaultPipePath, "path to the local API Windows named pipe")
	tunName := fs.String("tun", clientnet.DefaultTUNName(), "TUN interface name")
	controlURL := fs.String("control", "", "optional default Control Plane URL (e.g. https://cp:8443)")
	connectOnStart := fs.Bool("connect-on-start", true, "connect tunnel on start if enrolled")
	verbose := fs.Bool("v", false, "enable debug logging")

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	return runDaemon(*stateDir, *pipePath, *tunName, *controlURL, *connectOnStart, *verbose)
}

func main() {
	if err := parseFlagsAndRun(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ensureServiceSID makes sure the service is configured with an unrestricted service SID,
// which the kill switch WFP filters use to match the daemon (research #38). `opensased
// install` sets it at creation; the MSI cannot (WiX rejects MsiServiceConfig), so the
// service sets it on itself. The SCM applies it from the next service start.
func ensureServiceSID(log *slog.Logger) {
	m, err := mgr.Connect()
	if err != nil {
		log.Warn("service SID: connect to service manager", "err", err)
		return
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Warn("service SID: open service", "err", err)
		return
	}
	defer func() { _ = s.Close() }()
	cfg, err := s.Config()
	if err != nil {
		log.Warn("service SID: read config", "err", err)
		return
	}
	if cfg.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED {
		return
	}
	cfg.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	if err := s.UpdateConfig(cfg); err != nil {
		log.Warn("service SID: update config", "err", err)
		return
	}
	log.Info("service SID type set to unrestricted; effective from the next service start")
}
