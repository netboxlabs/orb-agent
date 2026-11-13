package secretsmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	defaultDSVTLD = "com"
	// defaultDSVURLTemplate is filled in with the tenant, the TLD, the
	// resource ("token" or "secrets") and the secret path, which is empty for
	// the token or starts with a "/".
	defaultDSVURLTemplate = "https://%s.secretsvaultcloud.%s/v1/%s%s"
	defaultDSVTimeout     = 60 * time.Second
)

var _ Manager = (*dsvManager)(nil)

// dsvManager resolves ${dsv://…} placeholders against Delinea DevOps Secrets
// Vault (DSV) through its REST API. DSV is a distinct product from Delinea
// Secret Server (see delineaManager).
//
// It sends the requests dsv-sdk-go v2.2.0 sent, which it used before: for
// each read, a client-credentials token request, then the secret request with
// that token. The token is not kept past the read, as the agent did not keep
// the SDK's either.
type dsvManager struct {
	pollingBase

	config     config.DSVManager
	preLogger  *slog.Logger
	httpClient *http.Client
	// timeout bounds one read: its token request and its secret request.
	// Start sets it from config.Timeout when it is zero; tests set it
	// beforehand for a limit shorter than a second.
	timeout time.Duration
}

// dsvHTTPError is a non-2xx answer from DSV. Its message is the SDK's
// "<status>: <body>", with the body cut short, and left out when it is an
// HTML page.
type dsvHTTPError struct {
	StatusCode int
	Status     string // as in "404 Not Found"
	Body       string
}

func (e *dsvHTTPError) Error() string {
	if e.Body == "" {
		return e.Status
	}
	return e.Status + ": " + e.Body
}

// Start resolves env-var placeholders, validates the configuration, and
// prepares the HTTP client. It does NOT eagerly authenticate — the first
// secret lookup requests a token, so the first real lookup surfaces an auth
// error.
func (d *dsvManager) Start(ctx context.Context) error {
	envFields := []struct {
		name string
		ptr  *string
	}{
		{"tenant", &d.config.Tenant},
		{"client_id", &d.config.ClientID},
		{"client_secret", &d.config.ClientSecret},
		{"tld", &d.config.TLD},
		{"url_template", &d.config.URLTemplate},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving dsv %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if d.config.Schedule != nil {
		resolved, err := config.ResolveEnv(*d.config.Schedule)
		if err != nil {
			return fmt.Errorf("resolving dsv schedule from environment: %w", err)
		}
		*d.config.Schedule = resolved
	}

	d.preLogger.Info("starting secrets manager", "active", "dsv", "tenant", d.config.Tenant, "tld", d.config.TLD)

	if d.config.Tenant == "" {
		return fmt.Errorf("dsv: tenant is required")
	}
	if d.config.ClientID == "" {
		return fmt.Errorf("dsv: client_id is required")
	}
	if d.config.ClientSecret == "" {
		return fmt.Errorf("dsv: client_secret is required")
	}
	if d.config.TLD == "" {
		d.config.TLD = defaultDSVTLD
	}
	if d.config.URLTemplate == "" {
		d.config.URLTemplate = defaultDSVURLTemplate
	}

	if d.timeout == 0 {
		d.timeout = defaultDSVTimeout
		if d.config.Timeout != nil && *d.config.Timeout > 0 {
			d.timeout = time.Duration(*d.config.Timeout) * time.Second
		}
	}
	// The default transport, as the SDK used: it reads the proxy from the
	// environment. The time limit is the read's context, set by fetch.
	d.httpClient = &http.Client{}

	d.init(ctx, d.preLogger, "dsv", d.fetch)
	if err := d.startScheduler(d.config.Schedule); err != nil {
		return err
	}
	d.preLogger.Info("secrets manager started", "active", "dsv")
	return nil
}

// fetch reads one secret for a parsed placeholder body.
//
// Grammar:
//
//	<secret-path>/<field-key>
//
// The body is split on its last "/": everything before is the DSV secret path,
// and the final segment is a key inside the secret's data map.
func (d *dsvManager) fetch(body string) (string, error) {
	idx := strings.LastIndex(body, "/")
	if idx <= 0 || idx == len(body)-1 {
		return "", fmt.Errorf("invalid dsv reference %q: expected '<secret-path>/<field-key>'", body)
	}
	path := body[:idx]
	field := body[idx+1:]

	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()

	data, err := d.readSecret(ctx, path)
	if err != nil {
		return "", fmt.Errorf("dsv: get secret path=%q: %w", path, err)
	}

	raw, ok := data[field]
	if !ok {
		return "", fmt.Errorf("dsv: field %q not found in secret %q", field, body)
	}
	val, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("dsv: field %q is not a string in secret %q", field, body)
	}
	if val == "" {
		return "", fmt.Errorf("dsv: field %q is empty in secret %q", field, body)
	}
	return val, nil
}

// readSecret requests a token, then the secret at path, and returns the
// secret's data map.
func (d *dsvManager) readSecret(ctx context.Context, path string) (map[string]any, error) {
	token, err := d.accessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.urlFor("secrets", path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	answer, err := d.do(ctx, req)
	if err != nil {
		return nil, err
	}

	// The SDK decoded the whole secret; only its data map is used. JSON keys
	// match case-insensitively, as they did.
	var secret struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(answer, &secret); err != nil {
		return nil, fmt.Errorf("decoding the secret: %w", err)
	}
	return secret.Data, nil
}

// dsvTokenRequest is the client-credentials grant, in the field order and
// with the omissions the SDK's encoding had.
type dsvTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// accessToken exchanges the client credentials for an access token.
func (d *dsvManager) accessToken(ctx context.Context) (string, error) {
	grant, err := json.Marshal(dsvTokenRequest{
		GrantType:    "client_credentials",
		ClientID:     d.config.ClientID,
		ClientSecret: d.config.ClientSecret,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.urlFor("token", ""), bytes.NewReader(grant))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	answer, err := d.do(ctx, req)
	if err != nil {
		return "", err
	}

	var token struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(answer, &token); err != nil {
		return "", fmt.Errorf("unmarshaling token response: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("the token response carries no accessToken")
	}
	return token.AccessToken, nil
}

// do sends req and returns the body of a 2xx answer, or a *dsvHTTPError for
// any other status.
func (d *dsvManager) do(ctx context.Context, req *http.Request) ([]byte, error) {
	resp, err := d.httpClient.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("no answer within %s: %w", d.timeout, err)
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("no answer within %s: %w", d.timeout, err)
		}
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &dsvHTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimPrefix(nonHTMLBodySnippet(resp.Header.Get("Content-Type"), answer), ": "),
		}
	}
	return answer, nil
}

// urlFor fills in the URL template for a resource and a secret path, as the
// SDK did: the path, trimmed of its leading slashes, follows a single "/" and
// is inserted as written, so the request parses it as any URL would.
func (d *dsvManager) urlFor(resource, path string) string {
	if path != "" {
		path = "/" + strings.TrimLeft(path, "/")
	}
	return fmt.Sprintf(d.config.URLTemplate, d.config.Tenant, d.config.TLD, resource, path)
}
