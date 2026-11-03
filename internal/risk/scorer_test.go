package risk

import (
	"testing"

	"github.com/loowtime/netrivox/pkg/models"
)

func TestScorePrioritizesCriticalPossibleCVE(t *testing.T) {
	service := models.Service{
		State: "open", Category: "remote-access", Version: "1.0",
		Vulnerabilities: []models.Vulnerability{{ID: "CVE-test", CVSS: 9.8}},
	}
	Score(&service, nil)
	if service.RiskLevel != "high" || service.RiskScore < 60 || len(service.RiskFactors) == 0 {
		t.Fatalf("unexpected risk: %+v", service)
	}
}
