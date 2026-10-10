package checks

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
)

// fakeNode is a JSON-RPC server driven by a method -> raw JSON result map.
// Methods missing from the map answer with Geth's real "method not found"
// error (code -32601, text taken from go-ethereum rpc/errors.go).
type fakeNode struct {
	results map[string]string
	errors  map[string]string // method -> raw error object
	cors    string
	mu      sync.Mutex
	calls   []string
	srv     *httptest.Server
}

func newFake(results map[string]string) *fakeNode {
	f := &fakeNode{results: results, errors: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			if f.cors != "" {
				w.Header().Set("Access-Control-Allow-Origin", f.cors)
			}
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.calls = append(f.calls, req.Method)
		f.mu.Unlock()
		if e, ok := f.errors[req.Method]; ok {
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":` + e + `}`))
			return
		}
		if res, ok := f.results[req.Method]; ok {
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"the method ` + req.Method + ` does not exist/is not available"}}`))
	}))
	return f
}

func (f *fakeNode) client() *scanner.Client {
	return scanner.NewClientWithTimeout(f.srv.URL, 2*time.Second)
}

func run(t *testing.T, c Check, f *fakeNode) CheckResult {
	t.Helper()
	defer f.srv.Close()
	return c.Run(context.Background(), f.client(), DefaultOptions())
}

// httptest listens on 127.0.0.1, i.e. a loopback target.

func TestAdminProbesNeverMutate(t *testing.T) {
	f := newFake(map[string]string{})
	run(t, NewAdminAPI(), f)
	for _, m := range f.calls {
		if strings.Contains(strings.ToLower(m), "newaccount") || strings.Contains(m, "import") ||
			strings.Contains(m, "unlock") || strings.Contains(m, "send") || strings.Contains(m, "sign") {
			t.Errorf("scanner sent state-changing or sensitive method %q", m)
		}
	}
	if len(f.calls) == 0 {
		t.Fatal("no probes sent")
	}
}

func TestAllChecksOnlyUseAllowListedMethods(t *testing.T) {
	allowed := map[string]bool{
		"net_version": true, "admin_nodeInfo": true, "admin_peers": true, "personal_listWallets": true,
		"personal_listAccounts": true, "eth_accounts": true, "web3_clientVersion": true, "net_peerCount": true,
	}
	f := newFake(map[string]string{"eth_accounts": `["0x1"]`, "web3_clientVersion": `"Geth/v1.13.5-stable-aa/linux-amd64/go1.21"`, "net_peerCount": `"0x5"`})
	defer f.srv.Close()
	for _, c := range All() {
		c.Run(context.Background(), f.client(), DefaultOptions())
	}
	for _, m := range f.calls {
		if !allowed[m] {
			t.Errorf("method %q is not on the read-only allow-list", m)
		}
	}
}

func TestAdminExposed(t *testing.T) {
	r := run(t, NewAdminAPI(), newFake(map[string]string{"admin_nodeInfo": `{"name":"x"}`}))
	if r.Status != StatusFail || r.Passed {
		t.Fatalf("want FAIL, got %s", r.Status)
	}
	// target is loopback => severity capped at MEDIUM
	if r.Risk != RiskMedium {
		t.Errorf("loopback exposure should be MEDIUM, got %s", r.Risk)
	}
}

func TestAdminInvalidParamsMeansPresent(t *testing.T) {
	f := newFake(map[string]string{})
	f.errors["personal_listAccounts"] = `{"code":-32602,"message":"missing value for required argument 0"}`
	r := run(t, NewAdminAPI(), f)
	if r.Status != StatusFail {
		t.Fatalf("a method answering -32602 exists; want FAIL, got %s", r.Status)
	}
}

func TestAdminAbsent(t *testing.T) {
	r := run(t, NewAdminAPI(), newFake(map[string]string{}))
	if r.Status != StatusPass {
		t.Fatalf("want PASS, got %s %+v", r.Status, r.Details)
	}
}

func TestAdminAllUnknownIsError(t *testing.T) {
	f := newFake(map[string]string{})
	for _, m := range adminProbes {
		f.errors[m] = `{"code":-32000,"message":"internal failure"}`
	}
	if r := run(t, NewAdminAPI(), f); r.Status != StatusError {
		t.Fatalf("undeterminable result must be ERROR, got %s", r.Status)
	}
}

func TestUnreachableNodeIsNeverAPass(t *testing.T) {
	dead := scanner.NewClientWithTimeout("http://127.0.0.1:1", 500*time.Millisecond)
	for _, c := range All() {
		r := c.Run(context.Background(), dead, DefaultOptions())
		if r.Status == StatusPass {
			t.Errorf("%s reported PASS for an unreachable node", c.ID())
		}
	}
}

func TestAccountsUnlocked(t *testing.T) {
	f := newFake(map[string]string{
		"eth_accounts":         `["0xaaaa"]`,
		"personal_listWallets": `[{"url":"keystore://x","status":"Unlocked","accounts":[{"address":"0xaaaa"}]}]`,
	})
	r := run(t, NewAccounts(), f)
	if r.Status != StatusFail || r.Risk != RiskMedium { // HIGH capped for loopback
		t.Fatalf("got %s/%s", r.Status, r.Risk)
	}
	if r.Details.(map[string]interface{})["unlocked_accounts"] != 1 {
		t.Errorf("details: %+v", r.Details)
	}
}

func TestAccountsLockedIsLow(t *testing.T) {
	f := newFake(map[string]string{
		"eth_accounts":         `["0xaaaa"]`,
		"personal_listWallets": `[{"url":"keystore://x","status":"Locked","accounts":[{"address":"0xaaaa"}]}]`,
	})
	r := run(t, NewAccounts(), f)
	if r.Status != StatusFail || r.Risk != RiskLow {
		t.Fatalf("locked accounts: got %s/%s", r.Status, r.Risk)
	}
}

func TestAccountsStateUnknown(t *testing.T) {
	f := newFake(map[string]string{"eth_accounts": `["0xaaaa","0xbbbb"]`})
	r := run(t, NewAccounts(), f)
	if r.Status != StatusFail || !strings.Contains(r.Details.(map[string]interface{})["note"].(string), "could not be determined") {
		t.Fatalf("got %s %+v", r.Status, r.Details)
	}
}

func TestAccountsNone(t *testing.T) {
	if r := run(t, NewAccounts(), newFake(map[string]string{"eth_accounts": `[]`})); r.Status != StatusPass {
		t.Fatalf("got %s", r.Status)
	}
}

func TestAccountsMalformedResponse(t *testing.T) {
	if r := run(t, NewAccounts(), newFake(map[string]string{"eth_accounts": `"oops"`})); r.Status != StatusError {
		t.Fatalf("got %s", r.Status)
	}
}

func TestCORS(t *testing.T) {
	for cors, want := range map[string]Status{
		"*": StatusFail, probeOrigin: StatusFail, "null": StatusFail, "": StatusPass, "https://app.example": StatusPass,
	} {
		f := newFake(nil)
		f.cors = cors
		if r := run(t, NewCORS(), f); r.Status != want {
			t.Errorf("ACAO=%q: got %s want %s", cors, r.Status, want)
		}
	}
}

func TestTLS(t *testing.T) {
	c := func(u string) CheckResult {
		return NewTLS().Run(context.Background(), scanner.NewClient(u), DefaultOptions())
	}
	if r := c("https://rpc.example.com"); r.Status != StatusPass {
		t.Errorf("https: %s", r.Status)
	}
	if r := c("http://rpc.example.com:8545"); r.Status != StatusFail {
		t.Errorf("http remote: %s", r.Status)
	}
	if r := c("http://127.0.0.1:8545"); r.Status != StatusSkipped {
		t.Errorf("http loopback: %s", r.Status)
	}
	if r := c("ws://rpc.example.com"); r.Status != StatusError {
		t.Errorf("unsupported scheme: %s", r.Status)
	}
}

func TestRPCExposureLoopbackSkipped(t *testing.T) {
	r := run(t, NewRPCExposure(), newFake(map[string]string{"net_version": `"1"`}))
	if r.Status != StatusSkipped {
		t.Fatalf("loopback target cannot show public exposure; got %s", r.Status)
	}
}

// remoteClient makes the endpoint look like a remote host ("rpc.example.test")
// while the transport still delivers requests to the local test server.
func remoteClient(f *fakeNode) *scanner.Client {
	addr := strings.TrimPrefix(f.srv.URL, "http://")
	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	return scanner.NewClientWithHTTP("http://rpc.example.test:8545", hc)
}

func TestRPCExposureRemote(t *testing.T) {
	f := newFake(map[string]string{"net_version": `"1"`})
	defer f.srv.Close()
	r := NewRPCExposure().Run(context.Background(), remoteClient(f), DefaultOptions())
	if r.Status != StatusFail || r.Risk != RiskHigh {
		t.Fatalf("remote unauthenticated RPC: got %s/%s", r.Status, r.Risk)
	}
}

func TestRPCExposureRemoteWithAuthError(t *testing.T) {
	f := newFake(nil)
	f.errors["net_version"] = `{"code":-32000,"message":"Unauthorized: invalid api key"}`
	defer f.srv.Close()
	if r := NewRPCExposure().Run(context.Background(), remoteClient(f), DefaultOptions()); r.Status != StatusPass {
		t.Fatalf("auth error should pass, got %s", r.Status)
	}
}

func TestRPCExposureRemoteDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }))
	defer srv.Close()
	f := &fakeNode{srv: srv}
	if r := NewRPCExposure().Run(context.Background(), remoteClient(f), DefaultOptions()); r.Status != StatusPass {
		t.Fatalf("HTTP 401 means access control; got %s", r.Status)
	}
}

func TestAdminRemoteIsCritical(t *testing.T) {
	f := newFake(map[string]string{"admin_nodeInfo": `{}`})
	defer f.srv.Close()
	if r := NewAdminAPI().Run(context.Background(), remoteClient(f), DefaultOptions()); r.Risk != RiskCritical || r.Status != StatusFail {
		t.Fatalf("got %s/%s", r.Status, r.Risk)
	}
}

func TestAccountsRemoteUnlockedIsHigh(t *testing.T) {
	f := newFake(map[string]string{
		"eth_accounts":         `["0xaa"]`,
		"personal_listWallets": `[{"status":"Unlocked","accounts":[{"address":"0xaa"}]}]`,
	})
	defer f.srv.Close()
	if r := NewAccounts().Run(context.Background(), remoteClient(f), DefaultOptions()); r.Risk != RiskHigh {
		t.Fatalf("got %s", r.Risk)
	}
}

func TestAuthErrorHeuristic(t *testing.T) {
	for msg, want := range map[string]bool{
		"Unauthorized": true, "invalid api key": true, "forbidden origin": true,
		"the method net_version does not exist": false, "execution reverted": false,
	} {
		if got := looksLikeAuthError(msg); got != want {
			t.Errorf("looksLikeAuthError(%q) = %v", msg, got)
		}
	}
}

func TestClientVersion(t *testing.T) {
	ver := func(s string) CheckResult {
		b, _ := json.Marshal(s)
		return run(t, NewClientVersion(), newFake(map[string]string{"web3_clientVersion": string(b)}))
	}
	r := ver("Geth/v1.10.7-stable-aa/linux-amd64/go1.16")
	if r.Status != StatusFail || r.Risk != RiskHigh {
		t.Errorf("old geth: %s/%s", r.Status, r.Risk)
	}
	if r.Details.(map[string]interface{})["upgrade_to_at_least"] != "1.13.15" {
		t.Errorf("upgrade target: %v", r.Details.(map[string]interface{})["upgrade_to_at_least"])
	}
	if r := ver("Geth/v1.14.0-stable-aa/linux-amd64/go1.22"); r.Status != StatusPass {
		t.Errorf("new geth: %s", r.Status)
	}
	// The original tool called every non-matching client "passed". A client with
	// no data must be SKIPPED, not PASS.
	if r := ver("Nethermind/v1.0.0+abc/linux-x64/dotnet8"); r.Status != StatusSkipped {
		t.Errorf("uncovered client: %s", r.Status)
	}
	if r := ver("garbage"); r.Status != StatusSkipped {
		t.Errorf("garbage: %s", r.Status)
	}
}

func TestClientVersionRPCMissing(t *testing.T) {
	if r := run(t, NewClientVersion(), newFake(nil)); r.Status != StatusSkipped {
		t.Fatalf("got %s", r.Status)
	}
}

func TestPeerCount(t *testing.T) {
	for res, want := range map[string]Status{`"0x0"`: StatusFail, `"0x2"`: StatusFail, `"0x3"`: StatusPass, `"0x32"`: StatusPass, `"zzz"`: StatusError, `1`: StatusError} {
		if r := run(t, NewPeerCount(), newFake(map[string]string{"net_peerCount": res})); r.Status != want {
			t.Errorf("peers %s: got %s want %s", res, r.Status, want)
		}
	}
	if r := run(t, NewPeerCount(), newFake(nil)); r.Status != StatusSkipped {
		t.Errorf("unsupported: %s", r.Status)
	}
}

func TestAllIsSortedAndStable(t *testing.T) {
	a, b := All(), All()
	prev := 5
	for i, c := range a {
		if c.ID() != b[i].ID() {
			t.Fatal("order not deterministic")
		}
		if r := c.RiskLevel().Rank(); r > prev {
			t.Errorf("not sorted by severity at %s", c.ID())
		} else {
			prev = r
		}
	}
	ids := map[string]bool{}
	for _, c := range a {
		if ids[c.ID()] {
			t.Errorf("duplicate id %s", c.ID())
		}
		ids[c.ID()] = true
	}
}

func TestSummarizeAndWorst(t *testing.T) {
	rs := []CheckResult{
		{Status: StatusPass}, {Status: StatusFail, Risk: RiskLow}, {Status: StatusFail, Risk: RiskHigh},
		{Status: StatusError, Risk: RiskCritical}, {Status: StatusSkipped},
	}
	s := Summarize(rs)
	if s.Passed != 1 || s.Errors != 1 || s.Skipped != 1 || s.Failed[RiskHigh] != 1 || s.Failed[RiskLow] != 1 {
		t.Errorf("%+v", s)
	}
	if Worst(rs) != RiskHigh {
		t.Errorf("an ERROR must not count as a finding; worst=%s", Worst(rs))
	}
	if Worst(nil) != "" {
		t.Error("no failures => empty")
	}
}

func TestParseRisk(t *testing.T) {
	if r, ok := ParseRisk(" High "); !ok || r != RiskHigh {
		t.Error("High")
	}
	if _, ok := ParseRisk("none"); ok {
		t.Error("none is not a risk")
	}
}
