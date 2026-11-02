package scanner

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/loowtime/netrivox/internal/services"
	"github.com/loowtime/netrivox/pkg/models"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type PortScanner struct {
	Dialer         Dialer
	Timeout        time.Duration
	Workers        int
	GrabBanner     bool
	MaxBannerBytes int
}

type HostPortTarget struct {
	Host string
	Port int
}

func (s PortScanner) ScanHosts(ctx context.Context, hosts []string, ports []int) []models.Service {
	if len(hosts) == 0 || len(ports) == 0 {
		return []models.Service{}
	}
	if s.Dialer == nil {
		s.Dialer = &net.Dialer{}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	workers := s.Workers
	if workers < 1 {
		workers = 1
	}
	targets := make(chan HostPortTarget)
	results := make(chan models.Service, len(hosts)*len(ports))
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for target := range targets {
				results <- s.scanPort(ctx, target.Host, target.Port, timeout)
			}
		}()
	}
	go func() {
		defer close(targets)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case targets <- HostPortTarget{Host: host, Port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()
	services := make([]models.Service, 0, len(hosts)*len(ports))
	for service := range results {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].HostIP != services[j].HostIP {
			return services[i].HostIP < services[j].HostIP
		}
		return services[i].Port < services[j].Port
	})
	return services
}

type HostPortTarget struct {
	Host string
	Port int
}

func (s PortScanner) ScanHosts(ctx context.Context, hosts []string, ports []int) []models.Service {
	if len(hosts) == 0 || len(ports) == 0 {
		return []models.Service{}
	}
	if s.Dialer == nil {
		s.Dialer = &net.Dialer{}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	workers := s.Workers
	if workers < 1 {
		workers = 1
	}
	targets := make(chan HostPortTarget)
	results := make(chan models.Service, len(hosts)*len(ports))
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for target := range targets {
				results <- s.scanPort(ctx, target.Host, target.Port, timeout)
			}
		}()
	}
	go func() {
		defer close(targets)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case targets <- HostPortTarget{Host: host, Port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()
	services := make([]models.Service, 0, len(hosts)*len(ports))
	for service := range results {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].HostIP != services[j].HostIP {
			return services[i].HostIP < services[j].HostIP
		}
		return services[i].Port < services[j].Port
	})
	return services
}

func (s PortScanner) Scan(ctx context.Context, host string, ports []int) []models.Service {
	if s.Dialer == nil {
		s.Dialer = &net.Dialer{}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	workers := s.Workers
	if workers < 1 {
		workers = 1
	}
	results := make([]models.Service, len(ports))
	jobs := make(chan int)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				results[index] = s.scanPort(ctx, host, ports[index], timeout)
			}
		}()
	}
	for index := range ports {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			for pending := range results {
				if results[pending].State == "" {
					results[pending] = models.Service{
						HostIP: host, Port: ports[pending], Protocol: "tcp",
						State: "canceled", ObservedAt: time.Now(),
					}
				}
			}
			return results
		}
	}
	close(jobs)
	wait.Wait()
	return results
}

func (s PortScanner) scanPort(ctx context.Context, host string, port int, timeout time.Duration) models.Service {
	start := time.Now()
	service := models.Service{
		HostIP: host, Port: port, Protocol: "tcp", State: "closed", ObservedAt: start,
	}
	definition := services.Lookup(port)
	service.Name = definition.Name
	service.Category = definition.Category
	service.Description = definition.Description
	if port < 1 || port > 65535 {
		service.Duration = time.Since(start)
		return service
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.Dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		service.State = "open"
		if s.GrabBanner {
			service.Banner = readBanner(conn, s.MaxBannerBytes)
		}
		_ = conn.Close()
	} else if errors.Is(probeCtx.Err(), context.Canceled) {
		service.State = "canceled"
	} else if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
		service.State = "timeout"
	}

	service.Duration = time.Since(start)
	return service
}

func readBanner(conn net.Conn, maxBytes int) string {
	if maxBytes <= 0 || maxBytes > 4096 {
		maxBytes = 1024
	}
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buffer := make([]byte, maxBytes)
	count, err := conn.Read(buffer)
	if err != nil || count == 0 {
		return ""
	}
	for index, char := range buffer[:count] {
		if char < 32 && char != '\t' {
			buffer[index] = ' '
		}
	}
	return strings.TrimSpace(string(buffer[:count]))
}
