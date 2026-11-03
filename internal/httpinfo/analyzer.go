package httpinfo

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

type Analyzer struct {
	Timeout        time.Duration
	AllowUntrusted bool
	MaxBodyBytes   int64
}

func (a Analyzer) Inspect(ctx context.Context, host string, port int) (models.HTTPMetadata, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	target := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	parsed, err := url.Parse(target)
	if err != nil {
		return models.HTTPMetadata{}, fmt.Errorf("parse HTTP target: %w", err)
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxBody := a.MaxBodyBytes
	if maxBody <= 0 || maxBody > 1<<20 {
		maxBody = 256 << 10
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: a.AllowUntrusted, // Explicit opt-in for private/self-signed endpoints.
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return models.HTTPMetadata{}, fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header.Set("User-Agent", "netrivox/"+version)
	response, err := client.Do(request)
	if err != nil {
		return models.HTTPMetadata{}, fmt.Errorf("inspect HTTP endpoint %s: %w", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return models.HTTPMetadata{}, fmt.Errorf("read HTTP response: %w", err)
	}
	metadata := models.HTTPMetadata{
		URL: target, StatusCode: response.StatusCode,
		Server:          response.Header.Get("Server"),
		PoweredBy:       response.Header.Get("X-Powered-By"),
		SecurityHeaders: make(map[string]string),
		VerifiedTLS:     scheme != "https" || !a.AllowUntrusted,
		RedirectBlocked: response.StatusCode >= 300 && response.StatusCode < 400,
	}
	if match := titlePattern.FindSubmatch(body); len(match) == 2 {
		metadata.Title = strings.TrimSpace(string(match[1]))
	}
	for _, header := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		if value := response.Header.Get(header); value != "" {
			metadata.SecurityHeaders[header] = value
		} else {
			metadata.MissingSecurityHeaders = append(metadata.MissingSecurityHeaders, header)
		}
	}
	return metadata, nil
}

const version = "0.1.0"
