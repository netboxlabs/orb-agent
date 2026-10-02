package secretsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

	// defaultCCPEndpointPath is appended to a base URL. AIMWebService is only
	// the default IIS application name; CCP installed under another name is
	// configured by giving the full endpoint URL, which ends in ccpAPIPath.
	defaultCCPEndpointPath = "/AIMWebService/api/Accounts"
	ccpAPIPath             = "/api/Accounts"
)

var _ Manager = (*cyberarkManager)(nil)

// cyberarkManager resolves ${cyberark://…} placeholders against the CyberArk
// CCP REST endpoint (by default /AIMWebService/api/Accounts).
type cyberarkManager struct {
	pollingBase

	config     config.CyberArkManager
	preLogger  *slog.Logger
	endpoint   *url.URL
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

	c.preLogger.Info("starting secrets manager", "active", "cyberark", "url", c.config.URL)

	if c.config.URL == "" {
		return fmt.Errorf("cyberark: url is required")
	}
	if c.config.AppID == "" {
		return fmt.Errorf("cyberark: app_id is required")
	}
	if strings.Contains(c.config.AppID, "/") {
		return fmt.Errorf("cyberark: app_id %q must not contain '/'", c.config.AppID)
	}
	parsedURL, err := url.Parse(c.config.URL)
	if err != nil {
		return fmt.Errorf("cyberark: url %q does not parse: %w", c.config.URL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("cyberark: url %q must use http or https (got scheme %q)", c.config.URL, parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("cyberark: url %q must include a host", c.config.URL)
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return fmt.Errorf("cyberark: url %q must not contain a query string or fragment", c.config.URL)
	}
	// A URL already ending in /api/Accounts is the full endpoint; any other
	// URL is a base and gets the default web service path appended.
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")
	if !isCCPEndpointPath(parsedURL.Path) {
		parsedURL.Path += defaultCCPEndpointPath
	}
	c.endpoint = parsedURL

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
		// AppendCertsFromPEM returns true only when at least one certificate
		// successfully parsed. A file containing only a PEM private key, or
		// only a malformed certificate, leaves the pool empty — reject those
		// at startup rather than producing an unusable trust store at
		// connection time.
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("cyberark: ca_bundle %q contains no parseable certificates", c.config.CABundle)
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
	// Clone http.DefaultTransport so we keep proxy-from-environment, dial
	// timeouts, idle-conn settings, HTTP/2 negotiation, etc. — a bare
	// &http.Transport{} would silently regress all of those in
	// enterprise deployments that rely on HTTPS_PROXY for outbound traffic.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	c.init(ctx, c.preLogger, "cyberark", c.fetch)
	if err := c.startScheduler(c.config.Schedule); err != nil {
		return err
	}
	c.preLogger.Info("secrets manager started", "active", "cyberark", "endpoint", c.endpoint.Redacted())
	return nil
}

// ccpErrorEnvelope is the JSON CyberArk sends on non-2xx responses.
type ccpErrorEnvelope struct {
	ErrorCode string `json:"ErrorCode,omitempty"`
	ErrorMsg  string `json:"ErrorMsg,omitempty"`
}

// fetch performs the GET on the CCP endpoint for the parsed reference and
// returns the requested field. Defaults to the Content field
// (which holds the password in CCP's response model).
func (c *cyberarkManager) fetch(body string) (string, error) {
	ref, err := c.parseBody(body)
	if err != nil {
		return "", err
	}

	u := *c.endpoint
	q := u.Query()
	q.Set("AppID", ref.appID)
	q.Set("Safe", ref.safe)
	q.Set("Object", ref.object)
	if c.config.Reason != "" {
		q.Set("Reason", c.config.Reason)
	}
	u.RawQuery = q.Encode()

	// pollingBase.init populates c.ctx during Start. The defensive fallback
	// guards against callers (most notably tests) that construct the
	// manager directly and bypass Start; http.NewRequestWithContext errors
	// out on a nil ctx, so without this we'd surface an opaque failure
	// instead of a real request.
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
		// CCP reports a missing account as a 404 with its JSON error envelope.
		// A 404 without one comes from the web server: nothing is installed at
		// that path, which is a configuration error, not a missing account.
		if detail, ok := ccpError(bodyBytes); ok {
			return "", fmt.Errorf("cyberark: account not found: %s (AppID=%s Safe=%s Object=%s): %s",
				body, ref.appID, ref.safe, ref.object, detail)
		}
		return "", fmt.Errorf("cyberark: get account %s: no CCP web service at %s (HTTP 404 without a CCP error); "+
			"set url to the CCP base URL, or to the full endpoint URL ending in %s when CCP is not installed as AIMWebService",
			body, c.endpoint.Redacted(), ccpAPIPath)
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
	if detail, ok := ccpError(b); ok {
		return detail
	}
	return strings.TrimSpace(string(b))
}

// ccpError reports the message of CCP's JSON error envelope, and whether the
// body carried one.
func ccpError(b []byte) (string, bool) {
	var env ccpErrorEnvelope
	if err := json.Unmarshal(b, &env); err != nil || env.ErrorMsg == "" {
		return "", false
	}
	if env.ErrorCode != "" {
		return env.ErrorCode + ": " + env.ErrorMsg, true
	}
	return env.ErrorMsg, true
}

// isCCPEndpointPath reports whether a URL path already names the CCP endpoint.
// IIS paths are case-insensitive, so the match is too.
func isCCPEndpointPath(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), strings.ToLower(ccpAPIPath))
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
		if strings.Contains(appID, "/") {
			return cyberarkRef{}, fmt.Errorf("invalid cyberark reference %q: AppID override must not contain '/'", body)
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
