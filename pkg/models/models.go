package models

import "time"

const SchemaVersion = 1

type Scan struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	TargetCount   int       `json:"target_count"`
	HostCount     int       `json:"host_count"`
	SchemaVersion int       `json:"schema_version"`
}

type Host struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Reachable bool      `json:"reachable"`
	Observed  time.Time `json:"observed_at"`
}

type Service struct {
	HostIP            string          `json:"host_ip"`
	Port              int             `json:"port"`
	Protocol          string          `json:"protocol"`
	State             string          `json:"state"`
	Name              string          `json:"name,omitempty"`
	Category          string          `json:"category,omitempty"`
	Description       string          `json:"description,omitempty"`
	Banner            string          `json:"banner,omitempty"`
	Version           string          `json:"version,omitempty"`
	VersionConfidence string          `json:"version_confidence,omitempty"`
	VersionEvidence   string          `json:"version_evidence,omitempty"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities,omitempty"`
	RiskScore         int             `json:"risk_score,omitempty"`
	RiskLevel         string          `json:"risk_level,omitempty"`
	RiskFactors       []string        `json:"risk_factors,omitempty"`
	HTTP              *HTTPMetadata   `json:"http,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"`
	Duration          time.Duration   `json:"duration,omitempty"`
}

type HTTPMetadata struct {
	URL                    string            `json:"url"`
	StatusCode             int               `json:"status_code"`
	Server                 string            `json:"server,omitempty"`
	PoweredBy              string            `json:"powered_by,omitempty"`
	Title                  string            `json:"title,omitempty"`
	SecurityHeaders        map[string]string `json:"security_headers,omitempty"`
	MissingSecurityHeaders []string          `json:"missing_security_headers,omitempty"`
	RedirectBlocked        bool              `json:"redirect_blocked"`
	VerifiedTLS            bool              `json:"verified_tls,omitempty"`
}

type Vulnerability struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Summary     string  `json:"summary,omitempty"`
	Source      string  `json:"source"`
	Match       string  `json:"match"`
	MatchType   string  `json:"match_type"`
	Verified    bool    `json:"verified"`
	Confirmed   bool    `json:"confirmed"`
	Remediation string  `json:"remediation,omitempty"`
}

type TLSMetadata struct {
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Version           string    `json:"version,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	SANs              []string  `json:"sans,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	ExpiresIn         int       `json:"expires_in_days,omitempty"`
	ExpiryWarning     bool      `json:"expiry_warning"`
	Verified          bool      `json:"verified"`
	VerificationError string    `json:"verification_error,omitempty"`
}

type ScanResult struct {
	Scan     Scan          `json:"scan"`
	Hosts    []Host        `json:"hosts"`
	Services []Service     `json:"services"`
	TLS      []TLSMetadata `json:"tls,omitempty"`
}
