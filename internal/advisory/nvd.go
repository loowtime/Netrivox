package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	MaxResults int
}

type response struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []metric `json:"cvssMetricV31"`
				V30 []metric `json:"cvssMetricV30"`
				V2  []metric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type metric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func (c Client) Lookup(ctx context.Context, service, version string) ([]models.Vulnerability, error) {
	if strings.TrimSpace(service) == "" || strings.TrimSpace(version) == "" {
		return nil, nil
	}
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	query := url.Values{}
	query.Set("keywordSearch", service+" "+version)
	maxResults := c.MaxResults
	if maxResults <= 0 || maxResults > 50 {
		maxResults = 20
	}
	query.Set("resultsPerPage", strconv.Itoa(maxResults))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("create advisory request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "netrivox/"+version)
	client := c.HTTPClient
	if client == nil {
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	responseData, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query NVD: %w", err)
	}
	defer responseData.Body.Close()
	if responseData.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query NVD: HTTP %s", responseData.Status)
	}
	var payload response
	if err := json.NewDecoder(responseData.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	result := make([]models.Vulnerability, 0, len(payload.Vulnerabilities))
	for _, entry := range payload.Vulnerabilities {
		cve := entry.CVE
		severity, score := score(cve.Metrics)
		summary := ""
		for _, description := range cve.Descriptions {
			if description.Lang == "en" {
				summary = description.Value
				break
			}
		}
		result = append(result, models.Vulnerability{
			ID: cve.ID, Severity: severity, CVSS: score, Summary: summary,
			Source: "NVD", Match: "possible keyword match; affected product and version are not verified",
			MatchType: "keyword", Verified: false, Confirmed: false,
			Remediation: "Confirm the exact vendor advisory and upgrade or mitigate according to the vendor guidance.",
		})
	}
	return result, nil
}

func score(metrics struct {
	V31 []metric `json:"cvssMetricV31"`
	V30 []metric `json:"cvssMetricV30"`
	V2  []metric `json:"cvssMetricV2"`
}) (string, float64) {
	all := append(append(metrics.V31, metrics.V30...), metrics.V2...)
	if len(all) == 0 {
		return "", 0
	}
	return all[0].CVSSData.BaseSeverity, all[0].CVSSData.BaseScore
}
