package secretsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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

// ccpErrorEnvelope is the JSON CyberArk sends on non-2xx responses.
type ccpErrorEnvelope struct {
	ErrorCode string `json:"ErrorCode,omitempty"`
	ErrorMsg  string `json:"ErrorMsg,omitempty"`
}

// fetch performs the GET /AIMWebService/api/Accounts call for the parsed
// reference and returns the requested field. Defaults to the Content field
// (which holds the password in CCP's response model).
func (c *cyberarkManager) fetch(body string) (string, error) {
	ref, err := c.parseBody(body)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(c.baseURL + "/AIMWebService/api/Accounts")
	if err != nil {
		return "", fmt.Errorf("cyberark: bad url %q: %w", c.baseURL, err)
	}
	q := u.Query()
	q.Set("AppID", ref.appID)
	q.Set("Safe", ref.safe)
	q.Set("Object", ref.object)
	if c.config.Reason != "" {
		q.Set("Reason", c.config.Reason)
	}
	u.RawQuery = q.Encode()

	// c.ctx is set by pollingBase.init() in Start (Task 5). Defensive default
	// here because tests in Task 4 — and any caller that bypasses Start —
	// would otherwise hit http.NewRequestWithContext's nil-context error.
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("cyberark: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cyberark: get account %s (AppID=%s Safe=%s Object=%s): %w",
			body, ref.appID, ref.safe, ref.object, err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cyberark: read response for %s: %w", body, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("cyberark: account not found: %s (AppID=%s Safe=%s Object=%s): %s",
			body, ref.appID, ref.safe, ref.object, ccpErrorDetail(bodyBytes))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("cyberark: get account %s (AppID=%s Safe=%s Object=%s): HTTP %d: %s",
			body, ref.appID, ref.safe, ref.object, resp.StatusCode, ccpErrorDetail(bodyBytes))
	}

	var parsed map[string]any
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return "", fmt.Errorf("cyberark: decode response for %s: %w", body, err)
	}

	raw, ok := parsed[ref.field]
	if !ok {
		return "", fmt.Errorf("cyberark: field %q not found in response for %s (AppID=%s Safe=%s Object=%s)",
			ref.field, body, ref.appID, ref.safe, ref.object)
	}
	strValue, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("cyberark: field %q is not a string for %s", ref.field, body)
	}
	if strValue == "" {
		return "", fmt.Errorf("cyberark: field %q is empty for %s", ref.field, body)
	}
	return strValue, nil
}

// ccpErrorDetail extracts a human-readable message from a CCP non-2xx
// response. Falls back to the raw body when the JSON envelope isn't present.
func ccpErrorDetail(b []byte) string {
	var env ccpErrorEnvelope
	if err := json.Unmarshal(b, &env); err == nil && env.ErrorMsg != "" {
		if env.ErrorCode != "" {
			return env.ErrorCode + ": " + env.ErrorMsg
		}
		return env.ErrorMsg
	}
	return strings.TrimSpace(string(b))
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
