package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type PortScanner struct {
	Dialer  Dialer
	Timeout time.Duration
	Workers int
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
	if port < 1 || port > 65535 {
		service.Duration = time.Since(start)
		return service
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.Dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		service.State = "open"
		_ = conn.Close()
	} else if errors.Is(probeCtx.Err(), context.Canceled) {
		service.State = "canceled"
	} else if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
		service.State = "timeout"
	}
	service.Duration = time.Since(start)
	return service
}
