package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Call(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","result":"0x1","id":1}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	res, err := client.Call(context.Background(), "net_version", nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if string(res) != `"0x1"` {
		t.Errorf("Expected result 0x1, got %s", string(res))
	}
}
