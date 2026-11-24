//go:build !windows

// Command opensased is the OpenSASE desktop daemon (issue #31).
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/yuky2020/opensase/internal/clientnet"
	"github.com/yuky2020/opensase/internal/desktop"
)

const (
	defaultStateDir   = "/var/lib/opensase"
	defaultSocketPath = "/run/opensase/opensased.sock"
	defaultGroup      = "opensase"
)

func main() {
	var (
		stateDir       string
		socketPath     string
		group          string
		tunName        string
		controlURL     string
		connectOnStart bool
		verbose        bool
	)

	flag.StringVar(&stateDir, "state", defaultStateDir, "state directory (keys, certificate, cached snapshot)")
	flag.StringVar(&socketPath, "socket", defaultSocketPath, "path to the local API Unix domain socket")
	flag.StringVar(&group, "group", defaultGroup, "group granted access to the Unix socket")
	flag.StringVar(&tunName, "tun", clientnet.DefaultTUNName(), "TUN interface name")
	flag.StringVar(&controlURL, "control", "", "optional default Control Plane URL (e.g. https://cp:8443)")
	flag.BoolVar(&connectOnStart, "connect-on-start", true, "connect tunnel on start if enrolled")
	flag.BoolVar(&verbose, "v", false, "enable debug logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(log)

	// Ensure socket directory exists with mode 0750
	sockDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(sockDir, 0750); err != nil {
		log.Error("create socket directory failed", "dir", sockDir, "err", err)
		os.Exit(1)
	}

	// Determine socket permissions based on configured group
	sockMode := os.FileMode(0600)
	gid := -1
	if group != "" {
		grp, err := user.LookupGroup(group)
		if err != nil {
			log.Warn("group does not exist, falling back to root-only 0600", "group", group, "err", err)
		} else {
			if parsedGID, err := strconv.Atoi(grp.Gid); err == nil {
				gid = parsedGID
				sockMode = 0660
			}
		}
	}

	// Remove stale socket if present
	_ = os.Remove(socketPath)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		log.Error("listen on socket failed", "path", socketPath, "err", err)
		os.Exit(1)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	if err := os.Chmod(socketPath, sockMode); err != nil {
		log.Warn("chmod socket failed", "path", socketPath, "mode", sockMode, "err", err)
	}
	if gid >= 0 {
		_ = os.Chown(socketPath, -1, gid)
		_ = os.Chown(sockDir, -1, gid)
	}

	d, err := desktop.NewDaemon(desktop.Config{
		StateDir:    stateDir,
		SocketGroup: group,
		TUNName:     tunName,
		ControlURL:  controlURL,
		Logger:      log,
	})
	if err != nil {
		log.Error("initialize daemon failed", "err", err)
		os.Exit(1)
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("opensased running", "socket", socketPath, "group", group, "tun", tunName)

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
			os.Exit(1)
		}
	}
}
