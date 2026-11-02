package tlsinfo

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/loowtime/netrivox/pkg/models"
)

type Analyzer struct {
	Timeout        time.Duration
	ExpiryWarning  time.Duration
	AllowUntrusted bool
}

func (a Analyzer) Inspect(ctx context.Context, host string, port int) (models.TLSMetadata, error) {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	warning := a.ExpiryWarning
	if warning <= 0 {
		warning = 30 * 24 * time.Hour
	}
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return models.TLSMetadata{}, fmt.Errorf("connect TLS endpoint %s:%d: %w", host, port, err)
	}
	conn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: a.AllowUntrusted, // Explicitly opt-in for metadata-only inspection.
	})
	defer conn.Close()
	handshakeErr := conn.HandshakeContext(ctx)
	if handshakeErr != nil && !a.AllowUntrusted {
		return models.TLSMetadata{}, fmt.Errorf("complete verified TLS handshake for %s:%d: %w", host, port, handshakeErr)
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return models.TLSMetadata{}, fmt.Errorf("TLS server %s:%d returned no certificate", host, port)
	}
	cert := state.PeerCertificates[0]
	expiresIn := int(time.Until(cert.NotAfter).Hours() / 24)
	metadata := models.TLSMetadata{
		Host:          host,
		Port:          port,
		Version:       tlsVersion(state.Version),
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SANs:          append([]string(nil), cert.DNSNames...),
		NotAfter:      cert.NotAfter,
		ExpiresIn:     expiresIn,
		ExpiryWarning: time.Until(cert.NotAfter) <= warning,
		Verified:      handshakeErr == nil && len(state.VerifiedChains) > 0,
	}
	if handshakeErr != nil {
		metadata.VerificationError = handshakeErr.Error()
	} else if a.AllowUntrusted {
		metadata.VerificationError = "certificate verification was explicitly disabled"
	}
	return metadata, nil
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return strings.ToUpper(fmt.Sprintf("unknown (0x%x)", version))
	}
}
