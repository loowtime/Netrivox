package tlsinfo

import (
	"context"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestInspectRequiresTrustedCertificateByDefault(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	host, port := splitAddress(t, server.Listener.Addr().String())
	_, err := (Analyzer{Timeout: time.Second}).Inspect(context.Background(), host, port)
	if err == nil {
		t.Fatal("Inspect() accepted an untrusted certificate by default")
	}
}

func TestInspectMarksExplicitUntrustedInspection(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	host, port := splitAddress(t, server.Listener.Addr().String())
	metadata, err := (Analyzer{Timeout: time.Second, AllowUntrusted: true}).Inspect(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Verified || metadata.VerificationError == "" {
		t.Fatalf("unexpected trust metadata: %+v", metadata)
	}
}

func splitAddress(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
