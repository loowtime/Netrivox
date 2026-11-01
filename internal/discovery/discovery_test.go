package discovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestExpandTargetsDeduplicatesAndSorts(t *testing.T) {
	got, err := ExpandTargets([]string{"192.0.2.2", "192.0.2.1/32", "192.0.2.2"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ExpandTargets() = %v, want %v", got, want)
	}
}

func TestExpandTargetsEnforcesLimit(t *testing.T) {
	if _, err := ExpandTargets([]string{"192.0.2.0/24"}, 10); !errors.Is(err, ErrHostLimitExceeded) {
		t.Fatalf("ExpandTargets() error = %v, want %v", err, ErrHostLimitExceeded)
	}
}

type fakeDialer struct{}

func (fakeDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type fakeResolver struct{}

func (fakeResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"host.example."}, nil
}

func TestDiscoverHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner := Scanner{
		Dialer: fakeDialer{}, Resolver: fakeResolver{}, Timeout: time.Second,
		Workers: 1, MaxHosts: 1, ProbePort: 443,
	}
	if _, err := scanner.Discover(ctx, []string{"192.0.2.1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover() error = %v, want context.Canceled", err)
	}
}
