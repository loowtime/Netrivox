package versioning

import (
	"regexp"
	"strings"

	"github.com/loowtime/netrivox/pkg/models"
)

var versionPattern = regexp.MustCompile(`(?i)[/_ -]([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-z]+\d*)?)`)

func Detect(service, banner string) (version, confidence, evidence string) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "", "none", ""
	}
	search := banner
	if service != "" {
		if index := strings.LastIndex(strings.ToLower(banner), strings.ToLower(service)); index >= 0 {
			search = banner[index+len(service):]
		}
	}
	match := versionPattern.FindStringSubmatch(search)
	if len(match) < 2 {
		return "", "none", banner
	}
	version = strings.TrimSpace(match[1])
	confidence = "medium"
	if strings.Contains(strings.ToLower(banner), strings.ToLower(service)) {
		confidence = "high"
	}
	return version, confidence, banner
}

func Enrich(service *models.Service) {
	if service == nil || service.Banner == "" {
		return
	}
	service.Version, service.VersionConfidence, service.VersionEvidence = Detect(service.Name, service.Banner)
}
