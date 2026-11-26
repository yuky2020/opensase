// Command opensase controls the OpenSASE desktop daemon (opensased) through its local API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/yuky2020/opensase/internal/desktop"
)

type usageError struct {
	msg string
}

func (e *usageError) Error() string {
	return e.msg
}

func usageErr(format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...)}
}

type globals struct {
	endpoint string
	jsonOut  bool
	timeout  time.Duration
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `usage: opensase [global flags] <command> [flags]

commands:
  status                   print client status
  connect                  connect the VPN tunnel
  disconnect               disconnect the VPN tunnel
  enroll -control URL      enroll device with the Control Plane
                           [-key-file F | -sso TENANT] (-sso: sign in with the identity provider)
  unenroll [-yes]          unenroll device
  flows [-n 50]            list recent traffic flows
  events [-f]              stream engine events
  version                  print version

global flags:
  -socket PATH / -pipe PATH (default: %s)
  -json                    print raw JSON output
  -timeout DUR             command timeout (default 15s)
`, defaultEndpoint)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func formatStatus(st map[string]any) string {
	var parts []string

	if state, ok := st["state"].(string); ok && state != "" {
		parts = append(parts, fmt.Sprintf("State: %s", state))
	}
	if enrolled, ok := st["enrolled"].(bool); ok {
		if enrolled {
			parts = append(parts, "Enrolled: yes")
		} else {
			parts = append(parts, "Enrolled: no")
		}
	}
	if edge, ok := st["edge"].(string); ok && edge != "" {
		parts = append(parts, fmt.Sprintf("Edge: %s", edge))
	}
	if kex, ok := st["kex"].(string); ok && kex != "" {
		parts = append(parts, fmt.Sprintf("PQ: %s", kex))
	} else if pq, ok := st["pq"].(bool); ok && pq {
		parts = append(parts, "PQ: true")
	}
	if v, exists := st["snapshotVersion"]; exists {
		var isStale bool
		if stale, ok := st["stale"].(bool); ok && stale {
			isStale = true
		}
		staleSuffix := ""
		if isStale {
			staleSuffix = " (stale)"
		}
		var verStr string
		switch val := v.(type) {
		case float64:
			verStr = strconv.FormatInt(int64(val), 10)
		case int, int64, uint64:
			verStr = fmt.Sprint(val)
		default:
			verStr = fmt.Sprint(val)
		}
		parts = append(parts, fmt.Sprintf("Policy: v%s%s", verStr, staleSuffix))
	}
	if errStr, ok := st["error"].(string); ok && errStr != "" {
		parts = append(parts, fmt.Sprintf("Error: %s", errStr))
	}
	return strings.Join(parts, "  ")
}

func formatFlowsTable(flows []map[string]any) string {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTION\tPROTOCOL\tDESTINATION\tAPP")
	for _, rec := range flows {
		timeStr := "-"
		if startVal, ok := rec["start"].(string); ok && startVal != "" {
			if t, err := time.Parse(time.RFC3339, startVal); err == nil {
				timeStr = t.Local().Format("15:04:05")
			} else if t, err := time.Parse(time.RFC3339Nano, startVal); err == nil {
				timeStr = t.Local().Format("15:04:05")
			} else {
				timeStr = startVal
			}
		}

		actionStr := "-"
		if dec, ok := rec["decision"].(map[string]any); ok {
			if a, ok := dec["action"].(string); ok && a != "" {
				actionStr = a
			}
		} else if a, ok := rec["action"].(string); ok && a != "" {
			actionStr = a
		}

		protoStr := "-"
		dstStr := "-"
		appStr := ""
		if fl, ok := rec["flow"].(map[string]any); ok {
			if p, ok := fl["protocol"].(string); ok && p != "" {
				protoStr = p
			}
			domain, _ := fl["domain"].(string)
			dstIP, _ := fl["dstIp"].(string)
			var dstPort uint16
			if pVal, ok := fl["dstPort"].(float64); ok {
				dstPort = uint16(pVal)
			} else if pVal, ok := fl["dstPort"].(int); ok {
				dstPort = uint16(pVal)
			}

			if domain != "" {
				dstStr = domain
			} else if dstIP != "" {
				if dstPort > 0 {
					dstStr = net.JoinHostPort(dstIP, strconv.Itoa(int(dstPort)))
				} else {
					dstStr = dstIP
				}
			}
			if app, ok := fl["app"].(string); ok && app != "" {
				appStr = app
			}
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", timeStr, actionStr, protoStr, dstStr, appStr)
	}
	_ = tw.Flush()
	return buf.String()
}

func runStatus(ctx context.Context, client *desktop.Client, jsonOut bool) error {
	st, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(st)
	}
	line := formatStatus(st)
	if line != "" {
		fmt.Println(line)
	}
	return nil
}

func runConnect(ctx context.Context, client *desktop.Client, jsonOut bool) error {
	if err := client.Connect(ctx); err != nil {
		return err
	}
	st, err := client.Status(ctx)
	if err != nil {
		if jsonOut {
			return printJSON(map[string]any{"connected": true, "state": "connected"})
		}
		fmt.Println("State: connected")
		return nil
	}
	if jsonOut {
		return printJSON(st)
	}
	line := formatStatus(st)
	if line == "" {
		line = "State: connected"
	}
	fmt.Println(line)
	return nil
}

func runDisconnect(ctx context.Context, client *desktop.Client, jsonOut bool) error {
	if err := client.Disconnect(ctx); err != nil {
		return err
	}
	st, err := client.Status(ctx)
	if err != nil {
		if jsonOut {
			return printJSON(map[string]any{"connected": false, "state": "stopped"})
		}
		fmt.Println("State: stopped")
		return nil
	}
	if jsonOut {
		return printJSON(st)
	}
	line := formatStatus(st)
	if line == "" {
		line = "State: stopped"
	}
	fmt.Println(line)
	return nil
}

func runEnroll(client *desktop.Client, args []string, jsonOut bool, timeout time.Duration) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	controlURL := fs.String("control", "", "Control Plane URL")
	name := fs.String("name", "", "device name (default hostname)")
	keyFile := fs.String("key-file", "", "file containing provisioning key")
	sso := fs.String("sso", "", "sign in with the organisation's identity provider instead of a key: the tenant ID (issue #68)")

	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *controlURL == "" {
		return usageErr("-control URL is required")
	}

	devName := *name
	if devName == "" {
		hostname, err := os.Hostname()
		if err == nil && hostname != "" {
			devName = hostname
		} else {
			devName = "device"
		}
	}

	var key []byte
	var readErr error
	if *sso != "" {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Minute)
		key, readErr = ssoKey(sctx, *controlURL, *sso)
		scancel()
		if readErr != nil {
			return readErr
		}
	} else if *keyFile != "" {
		key, readErr = os.ReadFile(*keyFile)
		if readErr != nil {
			return fmt.Errorf("read key file: %w", readErr)
		}
	} else if envKey := os.Getenv("OPENSASE_PROVISIONING_KEY"); envKey != "" {
		key = []byte(envKey)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Enter provisioning key: ")
		key, readErr = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if readErr != nil {
			return fmt.Errorf("read provisioning key: %w", readErr)
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return fmt.Errorf("read provisioning key from stdin: %w", err)
		}
		key = line
	}

	key = bytes.TrimSpace(key)
	defer clear(key)

	if len(key) == 0 {
		return usageErr("provisioning key is empty")
	}

	// The timeout starts after the key prompt, so a slow typist does not expire it.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := client.Enroll(ctx, *controlURL, string(key), devName); err != nil {
		return err
	}

	if jsonOut {
		return printJSON(map[string]any{"enrolled": true})
	}
	fmt.Println("Device enrolled successfully.")
	return nil
}

func runUnenroll(client *desktop.Client, args []string, jsonOut bool, timeout time.Duration) error {
	fs := flag.NewFlagSet("unenroll", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "confirm unenroll without prompting")

	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}

	if !*yes {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Unenroll this device? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read confirmation: %w", err)
			}
			input = strings.TrimSpace(input)
			if input != "y" && input != "Y" {
				fmt.Fprintln(os.Stderr, "Unenroll cancelled.")
				return nil
			}
		} else {
			return usageErr("unenroll requires -yes when not run from a terminal")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := client.Unenroll(ctx); err != nil {
		return err
	}

	if jsonOut {
		return printJSON(map[string]any{"enrolled": false})
	}
	fmt.Println("Device unenrolled.")
	return nil
}

func runFlows(ctx context.Context, client *desktop.Client, args []string, jsonOut bool) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	limit := fs.Int("n", 50, "maximum number of flow records")

	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}

	flows, err := client.Flows(ctx, *limit)
	if err != nil {
		return err
	}

	if jsonOut {
		return printJSON(flows)
	}

	table := formatFlowsTable(flows)
	fmt.Print(table)
	return nil
}

func runEvents(globalCtx context.Context, client *desktop.Client, args []string, jsonOut bool) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	follow := fs.Bool("f", false, "follow event stream until interrupted")

	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}

	printEv := func(ev desktop.Event) {
		if jsonOut {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s  %s\n", ev.Kind, ev.Payload)
		}
	}

	if *follow {
		// Follow mode runs until interrupted: WithoutCancel drops the -timeout deadline.
		ctx, cancel := signal.NotifyContext(context.WithoutCancel(globalCtx), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		err := client.Events(ctx, func(ev desktop.Event) error {
			printEv(ev)
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}

	ctx, cancel := context.WithCancel(globalCtx)
	defer cancel()

	idleTimer := time.NewTimer(1 * time.Second)
	defer idleTimer.Stop()

	go func() {
		select {
		case <-idleTimer.C:
			cancel()
		case <-ctx.Done():
		}
	}()

	err := client.Events(ctx, func(ev desktop.Event) error {
		printEv(ev)
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(1 * time.Second)
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func getVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func runVersion(jsonOut bool) error {
	v := getVersion()
	if jsonOut {
		return printJSON(map[string]string{"version": v})
	}
	fmt.Println(v)
	return nil
}

func run(args []string) int {
	fs := flag.NewFlagSet("opensase", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var g globals
	registerEndpointFlag(fs, &g.endpoint)
	fs.BoolVar(&g.jsonOut, "json", false, "print raw JSON output")
	fs.DurationVar(&g.timeout, "timeout", 15*time.Second, "command timeout")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(os.Stdout)
			return 0
		}
		fmt.Fprintf(os.Stderr, "opensase: %v\n", err)
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	subcmd := remaining[0]
	subArgs := remaining[1:]

	if subcmd == "version" {
		if err := runVersion(g.jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "opensase: %v\n", err)
			return 1
		}
		return 0
	}

	dial := dialEndpoint(g.endpoint)
	client := desktop.NewClient(dial)

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	var err error
	switch subcmd {
	case "status":
		err = runStatus(ctx, client, g.jsonOut)
	case "connect":
		err = runConnect(ctx, client, g.jsonOut)
	case "disconnect":
		err = runDisconnect(ctx, client, g.jsonOut)
	case "enroll":
		err = runEnroll(client, subArgs, g.jsonOut, g.timeout)
	case "unenroll":
		err = runUnenroll(client, subArgs, g.jsonOut, g.timeout)
	case "flows":
		err = runFlows(ctx, client, subArgs, g.jsonOut)
	case "events":
		err = runEvents(ctx, client, subArgs, g.jsonOut)
	default:
		err = usageErr("unknown command %q", subcmd)
	}

	if err != nil {
		var ue *usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "opensase: %s\n", ue.Error())
			return 2
		}
		if isNotExist(err, g.endpoint) {
			fmt.Fprintf(os.Stderr, "opensase: daemon is not running (start it with %s)\n", daemonStartHint)
			return 1
		}
		fmt.Fprintf(os.Stderr, "opensase: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}
