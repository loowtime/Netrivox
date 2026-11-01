package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanReportsOpenPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	results := (PortScanner{Timeout: time.Second, Workers: 2}).Scan(context.Background(), "127.0.0.1", []int{port, 0})
	if results[0].State != "open" {
		t.Fatalf("open port state = %q", results[0].State)
	}
	if results[1].State != "closed" {
		t.Fatalf("invalid port state = %q", results[1].State)
	}
}

func TestScanHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := (PortScanner{Timeout: time.Second, Workers: 1}).Scan(ctx, "192.0.2.1", []int{443})
	if len(results) != 1 || results[0].State != "canceled" {
		t.Fatalf("Scan() = %+v, want canceled result", results)
	}
}
