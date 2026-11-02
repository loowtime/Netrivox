package export

import (
	"bytes"
	"strings"
	"testing"

	"github.com/loowtime/netrivox/pkg/models"
)

func TestCSVExportsServices(t *testing.T) {
	var output bytes.Buffer
	err := CSV(&output, models.ScanResult{Services: []models.Service{{
		HostIP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "open",
		Name: "https", Category: "web",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "192.0.2.1,443,tcp,open,https,web") {
		t.Fatalf("unexpected CSV output: %q", output.String())
	}
}

func TestTableOnlyShowsOpenServices(t *testing.T) {
	var output bytes.Buffer
	err := Table(&output, models.ScanResult{Services: []models.Service{
		{HostIP: "192.0.2.1", Port: 22, State: "open", Name: "ssh"},
		{HostIP: "192.0.2.1", Port: 80, State: "closed", Name: "http"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "ssh") || strings.Contains(output.String(), "http") {
		t.Fatalf("unexpected table output: %q", output.String())
	}
}
