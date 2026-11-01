package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

var ErrHostLimitExceeded = errors.New("authorized targets exceed max_hosts")

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Resolver interface {
	LookupAddr(context.Context, string) ([]string, error)
}

type Scanner struct {
	Dialer    Dialer
	Resolver  Resolver
	Timeout   time.Duration
	Workers   int
	MaxHosts  int
	ProbePort int
}

func (s Scanner) Discover(ctx context.Context, targets []string) ([]models.Host, error) {
	ips, err := ExpandTargets(targets, s.MaxHosts)
	if err != nil {
		return nil, err
	}
	if s.Dialer == nil {
		s.Dialer = &net.Dialer{}
	}
	if s.Resolver == nil {
		s.Resolver = net.DefaultResolver
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	workers := s.Workers
	if workers < 1 {
		workers = 1
	}
	probePort := s.ProbePort
	if probePort < 1 || probePort > 65535 {
		probePort = 443
	}
	results := make([]models.Host, len(ips))
	jobs := make(chan int)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	for range workers {
		go func() {
			for index := range jobs {
				results[index] = s.probe(ctx, ips[index], probePort, timeout)
			}
			done <- struct{}{}
		}()
	}
	for index := range ips {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			for range workers {
				<-done
			}
			return nil, ctx.Err()
		}
	}
	close(jobs)
	for range workers {
		<-done
	}
	return results, nil
}

func (s Scanner) probe(ctx context.Context, ip string, port int, timeout time.Duration) models.Host {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := s.Dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	host := models.Host{IP: ip, Observed: start}
	if err == nil {
		host.Reachable = true
		_ = conn.Close()
	}
	if names, lookupErr := s.Resolver.LookupAddr(probeCtx, ip); lookupErr == nil && len(names) > 0 {
		host.Hostname = names[0]
	}
	return host
}

func ExpandTargets(targets []string, maxHosts int) ([]string, error) {
	if maxHosts < 1 {
		return nil, fmt.Errorf("max_hosts must be at least 1")
	}
	seen := make(map[string]struct{})
	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			seen[ip.String()] = struct{}{}
			continue
		}
		ip, network, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("parse authorized target %q: %w", target, err)
		}
		for current := ip.Mask(network.Mask); network.Contains(current); incrementIP(current) {
			seen[current.String()] = struct{}{}
			if len(seen) > maxHosts {
				return nil, ErrHostLimitExceeded
			}
		}
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

func incrementIP(ip net.IP) {
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			return
		}
	}
}
