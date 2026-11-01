package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Resolver interface {
	LookupHost(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupTXT(context.Context, string) ([]string, error)
	LookupAddr(context.Context, string) ([]string, error)
}

type Result struct {
	Name      string    `json:"name"`
	A         []string  `json:"a,omitempty"`
	AAAA      []string  `json:"aaaa,omitempty"`
	MX        []string  `json:"mx,omitempty"`
	NS        []string  `json:"ns,omitempty"`
	TXT       []string  `json:"txt,omitempty"`
	PTR       []string  `json:"ptr,omitempty"`
	QueriedAt time.Time `json:"queried_at"`
}

type Client struct {
	Resolver Resolver
	Timeout  time.Duration
}

func (c Client) Lookup(ctx context.Context, name string) (Result, error) {
	if name == "" {
		return Result{}, fmt.Errorf("DNS name must not be empty")
	}
	if c.Resolver == nil {
		c.Resolver = net.DefaultResolver
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := Result{Name: name, QueriedAt: time.Now()}
	ips, err := c.Resolver.LookupIPAddr(queryCtx, name)
	if err != nil {
		return result, fmt.Errorf("lookup IP records for %q: %w", name, err)
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			result.A = append(result.A, ip.IP.String())
		} else {
			result.AAAA = append(result.AAAA, ip.IP.String())
		}
	}
	mx, err := c.Resolver.LookupMX(queryCtx, name)
	if err != nil {
		return result, fmt.Errorf("lookup MX records for %q: %w", name, err)
	}
	for _, record := range mx {
		result.MX = append(result.MX, record.Host)
	}
	ns, err := c.Resolver.LookupNS(queryCtx, name)
	if err != nil {
		return result, fmt.Errorf("lookup NS records for %q: %w", name, err)
	}
	for _, record := range ns {
		result.NS = append(result.NS, record.Host)
	}
	if result.TXT, err = c.Resolver.LookupTXT(queryCtx, name); err != nil {
		return result, fmt.Errorf("lookup TXT records for %q: %w", name, err)
	}
	if result.PTR, err = c.Resolver.LookupAddr(queryCtx, name); err != nil {
		return result, fmt.Errorf("lookup PTR records for %q: %w", name, err)
	}
	return result, nil
}
