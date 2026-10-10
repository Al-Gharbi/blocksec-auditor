package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return NewClientWithTimeout(s.URL, 2*time.Second)
}

func TestCallResult(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","result":"0x1","id":1}`))
	})
	res, err := c.Call(context.Background(), "net_version")
	if err != nil || string(res) != `"0x1"` {
		t.Fatalf("got %s, %v", res, err)
	}
}

func TestCallSendsEmptyParamsArray(t *testing.T) {
	var body string
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.Write([]byte(`{"jsonrpc":"2.0","result":"x","id":1}`))
	})
	if _, err := c.Call(context.Background(), "web3_clientVersion"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"params":[]`) {
		t.Errorf("params must be an empty array, got %s", body)
	}
}

func TestRPCErrorIsTyped(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"the method admin_nodeInfo does not exist/is not available"},"id":1}`))
	})
	_, err := c.Call(context.Background(), "admin_nodeInfo")
	var re *RPCError
	if !errors.As(err, &re) || re.Code != CodeMethodNotFound {
		t.Fatalf("want typed RPCError -32601, got %v", err)
	}
	if !IsMethodNotFound(err) {
		t.Error("IsMethodNotFound should be true")
	}
}

func TestHTTPStatusWithoutJSON(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	_, err := c.Call(context.Background(), "net_version")
	if !IsAccessDenied(err) {
		t.Fatalf("want access denied, got %v", err)
	}
}

func TestNon2xxWithResultIsNotSuccess(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"0x1","id":1}`))
	})
	if _, err := c.Call(context.Background(), "net_version"); err == nil {
		t.Fatal("a 502 must not be reported as a successful call")
	}
}

func TestNonJSONOK(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hi</html>")) })
	if _, err := c.Call(context.Background(), "net_version"); err == nil {
		t.Fatal("HTML 200 is not a JSON-RPC server")
	}
}

func TestNoResultNoError(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"jsonrpc":"2.0","id":1}`)) })
	if _, err := c.Call(context.Background(), "x"); err == nil {
		t.Fatal("empty response must be an error")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	})
	_, err := c.Call(context.Background(), "net_version")
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusFound {
		t.Fatalf("redirect should surface as HTTP 302, got %v", err)
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","result":"`))
		chunk := []byte(strings.Repeat("A", 1<<16))
		for i := 0; i < 64; i++ { // 4 MiB
			w.Write(chunk)
		}
		w.Write([]byte(`","id":1}`))
	})
	if _, err := c.Call(context.Background(), "x"); err == nil {
		t.Fatal("oversized body must not parse")
	}
}

func TestPreflight(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions || r.Header.Get("Origin") != "https://evil.example" {
			t.Errorf("unexpected request %s origin=%q", r.Method, r.Header.Get("Origin"))
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
	})
	h, err := c.Preflight(context.Background(), "https://evil.example")
	if err != nil || h.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("%v %v", h, err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "127.5.5.5": true, "::1": true, "[::1]": true,
		"node.localhost": true, "0.0.0.0": false, "10.0.0.5": false, "example.com": false, "": false,
		"localhost.evil.com": false,
	} {
		if got := IsLoopbackHost(h); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestHost(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:8545": "127.0.0.1", "https://rpc.example.com/path": "rpc.example.com", "http://[::1]:8545": "::1",
	} {
		if got := NewClient(in).Host(); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}
