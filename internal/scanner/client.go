// Package scanner is a minimal, read-only JSON-RPC client used by the checks.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBody bounds how much of any response is read. A hostile node must not be
// able to exhaust the auditor's memory.
const maxBody = 1 << 20 // 1 MiB

// DefaultTimeout is the per-request timeout.
const DefaultTimeout = 10 * time.Second

// JSON-RPC error codes the checks care about.
const (
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
)

// Client talks JSON-RPC over HTTP(S).
type Client struct {
	Endpoint   string
	httpClient *http.Client
}

// NewClient returns a client with the default timeout.
func NewClient(endpoint string) *Client {
	return NewClientWithTimeout(endpoint, DefaultTimeout)
}

// NewClientWithTimeout returns a client with a custom per-request timeout.
// Redirects are not followed: a scanner must report what the target itself
// answers, not what a redirect target answers.
func NewClientWithTimeout(endpoint string, timeout time.Duration) *Client {
	return &Client{
		Endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Host returns the hostname of the endpoint (without port), or "" if the
// endpoint does not parse.
func (c *Client) Host() string {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// RPCRequest is a JSON-RPC 2.0 request.
type RPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// RPCResponse is a JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// RPCError is an error object returned by the node. It implements error so
// callers can use errors.As to read the code.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message) }

// HTTPError is returned when the server answers with a non-2xx status and the
// body is not a JSON-RPC response (typically 401/403 from a gateway).
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d", e.Status) }

// IsMethodNotFound reports whether err is a JSON-RPC "method not found".
func IsMethodNotFound(err error) bool {
	var re *RPCError
	return errors.As(err, &re) && re.Code == CodeMethodNotFound
}

// IsAccessDenied reports whether err is an HTTP 401/403.
func IsAccessDenied(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden)
}

// Call performs one JSON-RPC call. params may be nil (sent as an empty array,
// which every server accepts, unlike an omitted field).
func (c *Client) Call(ctx context.Context, method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}
	data, err := json.Marshal(RPCRequest{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	var rpcResp RPCResponse
	if jerr := json.Unmarshal(body, &rpcResp); jerr != nil {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, &HTTPError{Status: resp.StatusCode}
		}
		return nil, fmt.Errorf("response is not JSON-RPC: %w", jerr)
	}
	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &HTTPError{Status: resp.StatusCode}
	}
	if rpcResp.Result == nil {
		return nil, errors.New("response has neither result nor error")
	}
	return rpcResp.Result, nil
}

// Preflight sends an OPTIONS request with the given Origin and returns the
// response headers. Only headers are read; the body is discarded.
func (c *Client) Preflight(ctx context.Context, origin string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, c.Endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	return resp.Header, nil
}

// IsLoopbackHost reports whether host is localhost or a loopback IP literal.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	return isLoopbackIP(h)
}

func isLoopbackIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// NewClientWithHTTP returns a client that uses the supplied http.Client. It
// exists so tests can route a non-loopback hostname to a local test server.
func NewClientWithHTTP(endpoint string, hc *http.Client) *Client {
	return &Client{Endpoint: endpoint, httpClient: hc}
}
