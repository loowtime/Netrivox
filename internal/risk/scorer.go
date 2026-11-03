package risk

import (
	"fmt"
	"strings"

	"github.com/loowtime/netrivox/pkg/models"
)

func Score(service *models.Service, tlsMetadata *models.TLSMetadata) {
	if service == nil || service.State != "open" {
		return
	}
	score := 10
	factors := []string{"network service is reachable"}
	switch service.Category {
	case "remote-access":
		score += 20
		factors = append(factors, "remote administration surface")
	case "database", "file-sharing":
		score += 20
		factors = append(factors, "data access surface")
	}
	if service.Version == "" {
		score += 10
		factors = append(factors, "software version not identified")
	}
	if service.VersionConfidence == "low" {
		score += 5
		factors = append(factors, "low-confidence version evidence")
	}
	for _, vulnerability := range service.Vulnerabilities {
		if vulnerability.CVSS >= 9 {
			score += 45
			factors = append(factors, fmt.Sprintf("critical possible CVE %s", vulnerability.ID))
		} else if vulnerability.CVSS >= 7 {
			score += 30
			factors = append(factors, fmt.Sprintf("high possible CVE %s", vulnerability.ID))
		} else {
			score += 15
			factors = append(factors, fmt.Sprintf("possible CVE %s", vulnerability.ID))
		}
		if vulnerability.Confirmed {
			score += 15
			factors = append(factors, "CVE match confirmed")
		}
	}
	if tlsMetadata != nil && !tlsMetadata.Verified {
		score += 15
		factors = append(factors, "TLS certificate is not trusted")
	}
	if score > 100 {
		score = 100
	}
	service.RiskScore = score
	service.RiskLevel = level(score)
	service.RiskFactors = factors
}

func level(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func Summary(result models.ScanResult) string {
	counts := map[string]int{}
	for _, service := range result.Services {
		if service.RiskLevel != "" {
			counts[service.RiskLevel]++
		}
	}
	return fmt.Sprintf("risk: critical=%d high=%d medium=%d low=%d", counts["critical"], counts["high"], counts["medium"], counts["low"])
}

func IsHighRisk(service models.Service) bool {
	return strings.EqualFold(service.RiskLevel, "high") || strings.EqualFold(service.RiskLevel, "critical")
}
