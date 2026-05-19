package secretsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	defaultCyberArkTimeoutUnit = time.Second
	defaultCyberArkTimeout     = 60 * time.Second
)

var _ Manager = (*cyberarkManager)(nil)

// cyberarkManager resolves ${cyberark://…} placeholders against the CyberArk
// CCP REST endpoint (/AIMWebService/api/Accounts).
type cyberarkManager struct {
	pollingBase

	config     config.CyberArkManager
	preLogger  *slog.Logger
	baseURL    string
	httpClient *http.Client
}

// Start validates configuration, builds the TLS-aware HTTP client, and wires
// pollingBase. It does NOT eagerly authenticate; the first real lookup
// surfaces a 401/403 with a meaningful error.
func (c *cyberarkManager) Start(ctx context.Context) error {
	envFields := []struct {
		name string
		ptr  *string
	}{
		{"url", &c.config.URL},
		{"app_id", &c.config.AppID},
		{"reason", &c.config.Reason},
		{"ca_bundle", &c.config.CABundle},
		{"client_cert", &c.config.ClientCert},
		{"client_key", &c.config.ClientKey},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving cyberark %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if c.config.URL == "" {
		return fmt.Errorf("cyberark: url is required")
	}
	if c.config.AppID == "" {
		return fmt.Errorf("cyberark: app_id is required")
	}
	parsedURL, err := url.Parse(c.config.URL)
	if err != nil {
		return fmt.Errorf("cyberark: url %q does not parse: %w", c.config.URL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("cyberark: url %q must use http or https (got scheme %q)", c.config.URL, parsedURL.Scheme)
	}
	c.baseURL = strings.TrimRight(c.config.URL, "/")

	if (c.config.ClientCert == "") != (c.config.ClientKey == "") {
		return fmt.Errorf("cyberark: client_cert and client_key must both be set or both empty")
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: c.config.SkipTLSVerify} //nolint:gosec // operator opt-in
	if c.config.SkipTLSVerify {
		c.preLogger.Warn("cyberark: TLS peer verification disabled via skip_tls_verify")
	}

	if c.config.CABundle != "" {
		pemBytes, err := os.ReadFile(c.config.CABundle)
		if err != nil {
			return fmt.Errorf("cyberark: read ca_bundle %q: %w", c.config.CABundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			// AppendCertsFromPEM silently ignores junk; fail when the file
			// has no usable PEM blocks at all.
			if !containsPEMBlock(pemBytes) {
				return fmt.Errorf("cyberark: ca_bundle %q contains no PEM blocks", c.config.CABundle)
			}
		}
		tlsCfg.RootCAs = pool
	}

	if c.config.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(c.config.ClientCert, c.config.ClientKey)
		if err != nil {
			return fmt.Errorf("cyberark: load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	timeout := defaultCyberArkTimeout
	if c.config.Timeout != nil && *c.config.Timeout > 0 {
		timeout = time.Duration(*c.config.Timeout) * defaultCyberArkTimeoutUnit
	}
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// pollingBase wiring + scheduler are added in Task 5 once fetch exists.
	_ = ctx
	return nil
}

// containsPEMBlock returns true if bytes contain at least one valid PEM
// block.
func containsPEMBlock(b []byte) bool {
	block, _ := pem.Decode(b)
	return block != nil
}

// cyberarkRef holds a parsed placeholder body.
type cyberarkRef struct {
	appID  string
	safe   string
	object string
	field  string // "Content" when caller omitted the field segment
}

// parseBody decodes a placeholder body into (AppID, Safe, Object, Field).
// Grammar (see docs/secretsmgr/cyberark.md):
//
//	Short:               <Safe>/<Object>
//	Short+field:         <Safe>/<Object>/<Field>
//	Qualified:           <AppID>//<Safe>/<Object>
//	Qualified+field:     <AppID>//<Safe>/<Object>/<Field>
//
// The "//" separator unambiguously marks the end of an AppID override.
func (c *cyberarkManager) parseBody(body string) (cyberarkRef, error) {
	if body == "" {
		return cyberarkRef{}, fmt.Errorf("invalid cyberark reference: empty body")
	}

	var (
		appID     string
		remainder string
	)
	if idx := strings.Index(body, "//"); idx >= 0 {
		appID = body[:idx]
		remainder = body[idx+2:]
		if appID == "" {
			return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: empty AppID before '//'", body)
		}
	} else {
		appID = c.config.AppID
		remainder = body
	}

	if appID == "" {
		return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: short form requires sources.cyberark.app_id to be set", body)
	}

	parts := strings.Split(remainder, "/")
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: Safe and Object must be non-empty", body)
		}
		return cyberarkRef{appID: appID, safe: parts[0], object: parts[1], field: "Content"}, nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: Safe, Object and Field must be non-empty", body)
		}
		return cyberarkRef{appID: appID, safe: parts[0], object: parts[1], field: parts[2]}, nil
	default:
		return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: expected '<Safe>/<Object>[/<Field>]' (optionally prefixed by '<AppID>//')", body)
	}
}
