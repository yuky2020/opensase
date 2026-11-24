package desktop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Client communicates with the desktop daemon local API over a custom dialer (Unix socket or Windows named pipe).
type Client struct {
	hc *http.Client
}

// NewClient returns a new Client that dials using the provided dial function.
func NewClient(dial func(ctx context.Context) (net.Conn, error)) *Client {
	return &Client{
		hc: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dial(ctx)
				},
			},
		},
	}
}

func parseResponseError(resp *http.Response) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errResp)
	msg := errResp.Error
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s: %s (user must be in the opensase group (Linux) or enroll/unenroll need root/administrator)", resp.Status, msg)
	}
	return fmt.Errorf("%s: %s", resp.Status, msg)
}

// Status returns the current engine and daemon status map.
func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/status", nil)
	if err != nil {
		return nil, err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseResponseError(resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return st, nil
}

// Connect tells the daemon to bring up the tunnel.
func (c *Client) Connect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/connect", nil)
	if err != nil {
		return err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseResponseError(resp)
	}
	return nil
}

// Disconnect tells the daemon to bring down the tunnel.
func (c *Client) Disconnect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/disconnect", nil)
	if err != nil {
		return err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseResponseError(resp)
	}
	return nil
}

// Enroll enrolls the device with the Control Plane.
func (c *Client) Enroll(ctx context.Context, controlURL, provisioningKey, deviceName string) error {
	type enrollBody struct {
		ControlURL      string `json:"controlUrl"`
		ProvisioningKey string `json:"provisioningKey"`
		DeviceName      string `json:"deviceName"`
	}
	b, err := json.Marshal(enrollBody{
		ControlURL:      controlURL,
		ProvisioningKey: provisioningKey,
		DeviceName:      deviceName,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/enroll", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Host = "localhost"
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseResponseError(resp)
	}
	return nil
}

// Unenroll unenrolls the device.
func (c *Client) Unenroll(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/unenroll", nil)
	if err != nil {
		return err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseResponseError(resp)
	}
	return nil
}

// Flows fetches the recent flow records from the daemon.
func (c *Client) Flows(ctx context.Context, limit int) ([]map[string]any, error) {
	url := "http://localhost/v1/flows"
	if limit > 0 {
		url += "?limit=" + strconv.Itoa(limit)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseResponseError(resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var flows []map[string]any
	if err := json.Unmarshal(body, &flows); err != nil {
		return nil, fmt.Errorf("decode flows: %w", err)
	}
	if flows == nil {
		flows = []map[string]any{}
	}
	return flows, nil
}

// Events streams events from /v1/events and invokes fn for each received Event.
func (c *Client) Events(ctx context.Context, fn func(Event) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/events", nil)
	if err != nil {
		return err
	}
	req.Host = "localhost"

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseResponseError(resp)
	}

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 64*1024)

	var (
		currentEvent string
		dataLines    []string
	)

	stripLeadingSpace := func(s string) string {
		if strings.HasPrefix(s, " ") {
			return s[1:]
		}
		return s
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if currentEvent != "" || len(dataLines) > 0 {
				ev := Event{
					Kind:    currentEvent,
					Payload: strings.Join(dataLines, "\n"),
				}
				currentEvent = ""
				dataLines = dataLines[:0]
				if err := fn(ev); err != nil {
					return err
				}
			}
			continue
		}

		if strings.HasPrefix(line, ":") {
			// SSE comment, ignore
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = stripLeadingSpace(line[len("event:"):])
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, stripLeadingSpace(line[len("data:"):]))
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return err
	}

	return nil
}
