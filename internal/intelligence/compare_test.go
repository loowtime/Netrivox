package intelligence

import (
	"testing"

	"github.com/loowtime/netrivox/pkg/models"
)

func TestCompareReportsInfrastructureChanges(t *testing.T) {
	previous := models.ScanResult{
		Hosts:    []models.Host{{IP: "192.0.2.1", Reachable: true}},
		Services: []models.Service{{HostIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "open"}},
	}
	current := models.ScanResult{
		Hosts:    []models.Host{{IP: "192.0.2.1", Reachable: false}, {IP: "192.0.2.2", Reachable: true}},
		Services: []models.Service{{HostIP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "open"}},
	}
	changes := Compare(previous, current)
	if len(changes) != 4 {
		t.Fatalf("Compare() returned %d changes: %+v", len(changes), changes)
	}
}
