package httpinfo

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInspectCollectsHTTPMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte("<title>Internal Portal</title>"))
	}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	var port int
	_, _ = fmt.Sscan(portText, &port)
	result, err := (Analyzer{Timeout: time.Second}).Inspect(context.Background(), host, port)
	if err != nil || result.StatusCode != http.StatusOK || result.Title != "Internal Portal" || result.Server != "test-server" {
		t.Fatalf("Inspect() = %+v, %v", result, err)
	}
}
