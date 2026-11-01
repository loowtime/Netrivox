package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

type fakeResolver struct{}

func (fakeResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }
func (fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("2001:db8::1")}}, nil
}
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example."}}, nil
}
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns.example."}}, nil
}
func (fakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"v=spf1 -all"}, nil
}
func (fakeResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"host.example."}, nil
}

func TestLookupCollectsRecordTypes(t *testing.T) {
	result, err := (Client{Resolver: fakeResolver{}, Timeout: time.Second}).Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.A) != 1 || len(result.AAAA) != 1 || len(result.MX) != 1 || len(result.NS) != 1 || len(result.TXT) != 1 || len(result.PTR) != 1 {
		t.Fatalf("unexpected DNS result: %+v", result)
	}
}
