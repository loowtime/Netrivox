package risk

import (
	"testing"

	"github.com/loowtime/netrivox/pkg/models"
)

func TestViolationsUsesRiskThreshold(t *testing.T) {
	services := []models.Service{
		{RiskLevel: "low"},
		{RiskLevel: "high"},
		{RiskLevel: "critical"},
	}
	if got := Violations(services, "high"); len(got) != 2 {
		t.Fatalf("Violations() returned %d services, want 2", len(got))
	}
}
