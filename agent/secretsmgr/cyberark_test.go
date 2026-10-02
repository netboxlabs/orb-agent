package secretsmgr

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestCyberArkStart_RequiresURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "url is required")
}

func TestCyberArkStart_RequiresAppID(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "app_id is required")
}

func TestCyberArkStart_ResolvesEndpoint(t *testing.T) {
	// A base URL gets the default web service path appended; a URL already
	// ending in /api/Accounts is the full endpoint and is used as given, which
	// is how CCP installed under a non-default IIS application is reached.
	for _, tc := range []struct {
		url  string
		want string
	}{
		{"https://ccp.example.com", "https://ccp.example.com/AIMWebService/api/Accounts"},
		{"https://ccp.example.com/", "https://ccp.example.com/AIMWebService/api/Accounts"},
		{"https://ccp.example.com/cyberark", "https://ccp.example.com/cyberark/AIMWebService/api/Accounts"},
		{"https://ccp.example.com/AIMWebService/api/Accounts", "https://ccp.example.com/AIMWebService/api/Accounts"},
		{"https://ccp.example.com/AIMWebService/api/Accounts/", "https://ccp.example.com/AIMWebService/api/Accounts"},
		{"https://ccp.example.com/AIMWebServiceCustom/api/Accounts", "https://ccp.example.com/AIMWebServiceCustom/api/Accounts"},
		{"https://ccp.example.com/aimwebservicecustom/api/accounts", "https://ccp.example.com/aimwebservicecustom/api/accounts"},
		{"https://ccp.example.com/some/prefix/AIMWebService/api/Accounts", "https://ccp.example.com/some/prefix/AIMWebService/api/Accounts"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			c := &cyberarkManager{
				preLogger: newTestLogger(),
				config:    config.CyberArkManager{URL: tc.url, AppID: "orb"},
			}
			require.NoError(t, c.Start(context.Background()))
			require.Equal(t, tc.want, c.endpoint.String())
		})
	}
}

func TestCyberArkStart_RejectsURLWithQueryOrFragment(t *testing.T) {
	for _, bad := range []string{
		"https://ccp.example.com?x=y",
		"https://ccp.example.com#anchor",
		"https://ccp.example.com/cyberark?a=1",
	} {
		t.Run(bad, func(t *testing.T) {
			c := &cyberarkManager{
				preLogger: newTestLogger(),
				config:    config.CyberArkManager{URL: bad, AppID: "orb"},
			}
			err := c.Start(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "query string or fragment")
		})
	}
}

func TestCyberArkStart_RejectsURLWithoutHost(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "must include a host")
}

func TestCyberArkStart_RejectsAppIDWithSlash(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "team/app"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not contain '/'")
}

func TestCyberArkStart_RejectsCABundleWithOnlyPrivateKey(t *testing.T) {
	// A PEM file that has a recognisable PEM block but no certificate must
	// be rejected at startup rather than producing an empty trust pool that
	// fails opaquely at TLS handshake time. Generate the key at runtime via
	// the same helper the mTLS test uses, so there's no literal-looking
	// private-key material in the source tree to trip secret scanners.
	_, keyPEM := generateTestCertPair(t, "ca-bundle-key-only-fixture")

	dir := t.TempDir()
	keyOnly := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyOnly, keyPEM, 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: keyOnly},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no parseable certificates")
}

func TestCyberArkStart_RejectsUnparseableURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "ht tp://bad url", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not parse")
}

func TestCyberArkStart_RejectsNonHTTPScheme(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "ftp://ccp.example.com", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "http or https")
}

func TestCyberArkStart_DefaultTimeout(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))
	require.NotNil(t, c.httpClient)
	require.Equal(t, defaultCyberArkTimeout, c.httpClient.Timeout)
}

func TestCyberArkStart_CustomTimeout(t *testing.T) {
	timeoutSec := 5
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", Timeout: &timeoutSec},
	}
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, 5*defaultCyberArkTimeoutUnit, c.httpClient.Timeout)
}

func TestCyberArkStart_RequiresBothCertAndKey(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", ClientCert: "/tmp/cert.pem"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_key")

	c = &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", ClientKey: "/tmp/key.pem"},
	}
	err = c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_cert")
}

func TestCyberArkStart_RejectsMissingCABundle(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: "/nonexistent/ca.pem"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_bundle")
}

func TestCyberArkStart_RejectsCABundleWithNoPEMBlocks(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-a-pem.txt")
	require.NoError(t, os.WriteFile(bad, []byte("this is not pem"), 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: bad},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_bundle")
}

func TestCyberArkStart_AcceptsCABundle(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(testSelfSignedCAPEM), 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: caPath},
	}
	require.NoError(t, c.Start(context.Background()))
	require.NotNil(t, c.httpClient.Transport)

	tr := c.httpClient.Transport.(*http.Transport)
	require.NotNil(t, tr.TLSClientConfig)
	require.NotNil(t, tr.TLSClientConfig.RootCAs)
}

func TestCyberArkStart_SkipTLSVerifyFlowsThroughToTransport(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", SkipTLSVerify: true},
	}
	require.NoError(t, c.Start(context.Background()))
	tr := c.httpClient.Transport.(*http.Transport)
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func cyberarkManagerWith(appID string) *cyberarkManager {
	return &cyberarkManager{config: config.CyberArkManager{AppID: appID}}
}

func TestCyberArkParseBody_ShortForm(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "orb-agent", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "Content", ref.field)
}

func TestCyberArkParseBody_ShortFormWithField(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "orb-agent", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "UserName", ref.field)
}

func TestCyberArkParseBody_Qualified(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("OtherApp//Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "OtherApp", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "Content", ref.field)
}

func TestCyberArkParseBody_QualifiedWithField(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("OtherApp//Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "OtherApp", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "UserName", ref.field)
}

func TestCyberArkParseBody_GrammarErrors(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	for _, body := range []string{
		"",                                     // empty
		"Lab",                                  // 1 segment short — no object
		"Lab/DB-Account/UserName/Extra",        // 4 segments short — too long
		"OtherApp//Lab",                        // qualified short — no object
		"OtherApp//Lab/DB-Account/Field/Extra", // qualified too long
		"//Lab/DB-Account",                     // empty AppID before //
		"/Lab/DB-Account",                      // leading slash
		"Lab/",                                 // trailing slash
		"Lab//Object",                          // // with nothing after AppID makes no sense
	} {
		_, err := c.parseBody(body)
		require.Errorf(t, err, "body %q should have been rejected", body)
	}
}

func TestCyberArkParseBody_ShortFormRequiresConfiguredAppID(t *testing.T) {
	c := cyberarkManagerWith("")
	_, err := c.parseBody("Lab/DB-Account")
	require.Error(t, err)
	require.Contains(t, err.Error(), "app_id")
}

func TestCyberArkParseBody_RejectsAppIDOverrideContainingSlash(t *testing.T) {
	// The "//" separator marks the end of the AppID, so a body like
	// "A/B//Safe/Object" would otherwise leak the unsupported segment into
	// AppID=A/B. The docs claim "/" is reserved across all four name
	// segments; this lock guarantees the parser actually enforces it.
	c := cyberarkManagerWith("orb-agent")
	_, err := c.parseBody("A/B//Lab/DB-Account")
	require.Error(t, err)
	require.Contains(t, err.Error(), "AppID override must not contain '/'")
}

// fakeCCP emulates the GET /AIMWebService/api/Accounts endpoint, or the
// same endpoint under another web service name via newFakeCCPAt.
type fakeCCP struct {
	*httptest.Server
	mu       sync.Mutex
	accounts map[string]map[string]any // key = "<AppID>|<Safe>|<Object>"
	missing  map[string]bool
	calls    atomic.Int32
	lastReq  atomic.Value // url.Values
}

func newFakeCCP() *fakeCCP {
	return newFakeCCPAt("/AIMWebService/api/Accounts")
}

func newFakeCCPAt(endpointPath string) *fakeCCP {
	f := &fakeCCP{accounts: map[string]map[string]any{}, missing: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc(endpointPath, func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		q := r.URL.Query()
		f.lastReq.Store(q)
		key := q.Get("AppID") + "|" + q.Get("Safe") + "|" + q.Get("Object")

		f.mu.Lock()
		defer f.mu.Unlock()
		if f.missing[key] {
			http.Error(w, `{"ErrorCode":"APPAP004E","ErrorMsg":"Object not found"}`, http.StatusNotFound)
			return
		}
		acc, ok := f.accounts[key]
		if !ok {
			http.Error(w, `{"ErrorCode":"APPAP004E","ErrorMsg":"Object not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(acc)
	})
	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeCCP) set(appID, safe, object string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[appID+"|"+safe+"|"+object] = fields
}

func (f *fakeCCP) delete(appID, safe, object string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.accounts, appID+"|"+safe+"|"+object)
	f.missing[appID+"|"+safe+"|"+object] = true
}

func newCyberarkManagerForTest(t *testing.T, fake *fakeCCP, cfg config.CyberArkManager) *cyberarkManager {
	t.Helper()
	if cfg.AppID == "" {
		cfg.AppID = "orb-agent"
	}
	cfg.URL = fake.URL
	c := &cyberarkManager{preLogger: newTestLogger(), config: cfg}
	require.NoError(t, c.Start(context.Background()))
	return c
}

func TestCyberArkFetch_ShortForm_ReturnsContent(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "DB-Account", map[string]any{
		"Content":  "s3cret",
		"UserName": "dbuser",
	})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "orb-agent", q.Get("AppID"))
	require.Equal(t, "Lab", q.Get("Safe"))
	require.Equal(t, "DB-Account", q.Get("Object"))
}

func TestCyberArkFetch_FieldSelector_ReturnsUserName(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "DB-Account", map[string]any{
		"Content":  "s3cret",
		"UserName": "dbuser",
	})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "dbuser", val)
}

func TestCyberArkFetch_QualifiedAppID_OverridesYAML(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("OtherApp", "Lab", "DB-Account", map[string]any{"Content": "ot-secret"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("OtherApp//Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "ot-secret", val)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "OtherApp", q.Get("AppID"))
}

func TestCyberArkFetch_ReasonIsForwarded(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "x"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{Reason: "policy resolution"})
	_, err := c.fetch("Lab/Acc")
	require.NoError(t, err)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "policy resolution", q.Get("Reason"))
}

func TestCyberArkFetch_NotFound(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Missing")
	require.Error(t, err)
	require.Contains(t, err.Error(), "account not found")
	require.Contains(t, err.Error(), "APPAP004E: Object not found", "underlying CCP error must surface")
}

func TestCyberArkFetch_FullEndpointURL_NonDefaultWebService(t *testing.T) {
	fake := newFakeCCPAt("/AIMWebServiceCustom/api/Accounts")
	defer fake.Close()
	fake.set("orb-agent", "Lab", "DB-Account", map[string]any{"Content": "s3cret"})

	c := &cyberarkManager{preLogger: newTestLogger(), config: config.CyberArkManager{
		URL:   fake.URL + "/AIMWebServiceCustom/api/Accounts",
		AppID: "orb-agent",
	}}
	require.NoError(t, c.Start(context.Background()))
	val, err := c.fetch("Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val)
	require.Equal(t, int32(1), fake.calls.Load())
}

func TestCyberArkFetch_WebServer404IsNotAccountNotFound(t *testing.T) {
	// A 404 without a CCP error code comes from the web server: the configured
	// path has no CCP web service. It must not read as a missing account, and
	// the web server's HTML error page must not be dumped into the error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>404 - File or directory not found.</body></html>"))
	}))
	defer srv.Close()

	c := &cyberarkManager{preLogger: newTestLogger(), config: config.CyberArkManager{URL: srv.URL, AppID: "orb-agent"}}
	require.NoError(t, c.Start(context.Background()))
	_, err := c.fetch("Lab/DB-Account")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "account not found")
	require.NotContains(t, err.Error(), "DOCTYPE")
	require.Contains(t, err.Error(), "HTTP 404 from "+srv.URL+"/AIMWebService/api/Accounts without a CCP error body")
	require.Contains(t, err.Error(), "full endpoint URL ending in /api/Accounts", "the error must say how to reach a non-default web service")
}

func TestCyberArkFetch_WebServer404KeepsNonHTMLBody(t *testing.T) {
	// A gateway's own 404 body helps diagnose a proxy in front of CCP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no Route matched"}`))
	}))
	defer srv.Close()

	c := &cyberarkManager{preLogger: newTestLogger(), config: config.CyberArkManager{URL: srv.URL, AppID: "orb-agent"}}
	require.NoError(t, c.Start(context.Background()))
	_, err := c.fetch("Lab/DB-Account")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "account not found")
	require.Contains(t, err.Error(), `without a CCP error body: {"message":"no Route matched"}`)
}

func TestCyberArkFetch_GatewayErrorCodeIsNotCCP(t *testing.T) {
	// encoding/json decodes "errorCode" into ErrorCode, so only CCP's code
	// shape may classify a 404 as a missing account.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":"NotFound","message":"route"}`))
	}))
	defer srv.Close()

	c := &cyberarkManager{preLogger: newTestLogger(), config: config.CyberArkManager{URL: srv.URL, AppID: "orb-agent"}}
	require.NoError(t, c.Start(context.Background()))
	_, err := c.fetch("Lab/DB-Account")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "account not found")
	require.Contains(t, err.Error(), `{"errorCode":"NotFound","message":"route"}`)
}

func TestNonHTMLBodySnippet(t *testing.T) {
	long := strings.Repeat("a", maxBodySnippet+50)
	for _, tc := range []struct {
		name, contentType, body, want string
	}{
		{"html content type", "text/html; charset=utf-8", "anything", ""},
		{"html body without html content type", "text/plain", "<!DOCTYPE html><html>404</html>", ""},
		{"html body after a BOM", "", "\ufeff<!DOCTYPE html><html>404</html>", ""},
		{"xhtml with an xml prolog", "", `<?xml version="1.0"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN"><html>`, ""},
		{"page starting with head", "", "<head><title>404</title></head>", ""},
		{"body element alone", "", "<body>404</body>", ""},
		{"body element with attributes", "", `<body class="error">404</body>`, ""},
		{"html element alone", "", "<html>404</html>", ""},
		{"html element with attributes", "", `<html lang="en">404</html>`, ""},
		{"head element with attributes", "", `<head profile="x"><title>404</title></head>`, ""},
		{"html5 page without an html element", "", "<!doctype html><title>404</title>", ""},
		{"json mentioning a header tag is kept", "application/json", `{"message":"missing <header> X-Api-Key"}`, `: {"message":"missing <header> X-Api-Key"}`},
		{"empty body", "application/json", "   ", ""},
		{"whitespace collapsed", "application/json", "{\n  \"message\": \"no route\"\n}", `: { "message": "no route" }`},
		{"control characters dropped", "", "x\x1b[31mRED\x1b[0m\x00", ": x[31mRED[0m"},
		{"invalid utf-8 replaced", "", "ok\xff", ": ok\ufffd"},
		{"capped", "", long, ": " + long[:maxBodySnippet] + "…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, nonHTMLBodySnippet(tc.contentType, []byte(tc.body)))
		})
	}
}

func TestNonHTMLBodySnippet_BoundsLargeBodies(t *testing.T) {
	body := []byte(strings.Repeat("x", 10*maxBodyScan) + "<html>")
	require.Equal(t, ": "+strings.Repeat("x", maxBodySnippet)+"…", nonHTMLBodySnippet("", body),
		"only the first maxBodyScan bytes are inspected")
}

func TestCyberArkFetch_404WithOnlyErrorCodeIsAccountNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ErrorCode":"APPAP004E"}`))
	}))
	defer srv.Close()

	c := &cyberarkManager{preLogger: newTestLogger(), config: config.CyberArkManager{URL: srv.URL, AppID: "orb-agent"}}
	require.NoError(t, c.Start(context.Background()))
	_, err := c.fetch("Lab/DB-Account")
	require.Error(t, err)
	require.Contains(t, err.Error(), "account not found")
	require.Contains(t, err.Error(), "APPAP004E")
}

func TestCyberArkStart_LogsRedactedEndpoint(t *testing.T) {
	var buf bytes.Buffer
	c := &cyberarkManager{
		preLogger: slog.New(slog.NewJSONHandler(&buf, nil)),
		config:    config.CyberArkManager{URL: "https://svc:hunter2@ccp.example.com/AIMWebServiceCustom/api/Accounts", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))

	var started map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec["msg"] == "secrets manager started" {
			started = rec
		}
	}
	require.NotNil(t, started, "startup must log the resolved endpoint")
	require.Equal(t, "https://svc:xxxxx@ccp.example.com/AIMWebServiceCustom/api/Accounts", started["endpoint"])
	require.NotContains(t, buf.String(), "hunter2", "no startup log line may carry the url password")
}

func TestCyberArkStart_NeverEchoesURLPassword(t *testing.T) {
	// A password with an unescaped '/', '?' or '#' ends the authority early,
	// so net/url never reads it as userinfo and cannot mask it.
	for _, tc := range []struct {
		url       string
		forbidden []string
	}{
		{"ftp://svc:hunter2@ccp.example.com", []string{"hunter2"}},
		{"https://svc:hunter2@", []string{"hunter2"}},
		{"https://svc:hunter2@ccp.example.com?x=y", []string{"hunter2"}},
		{"https://svc:hunter2@ccp example.com/", []string{"hunter2"}},
		{"https://svc:hun/ter2@ccp.example.com", []string{"hun", "ter2"}},
		{"https://svc:12/ter2@ccp.example.com", []string{"svc:12", "ter2"}},
		{"https://svc:hun?ter2@ccp.example.com", []string{"hun", "ter2"}},
		{"https://svc:hun#ter2@ccp.example.com", []string{"hun", "ter2"}},
		{"https://svc:hun%zzter2@ccp.example.com", []string{"hun", "%zz", "ter2"}},
	} {
		t.Run(tc.url, func(t *testing.T) {
			var buf bytes.Buffer
			c := &cyberarkManager{
				preLogger: slog.New(slog.NewJSONHandler(&buf, nil)),
				config:    config.CyberArkManager{URL: tc.url, AppID: "orb"},
			}
			var messages []string
			if err := c.Start(context.Background()); err != nil {
				messages = append(messages, err.Error())
			} else {
				_, err := c.fetch("Lab/DB-Account")
				require.Error(t, err)
				messages = append(messages, err.Error())
			}
			messages = append(messages, buf.String())
			for _, m := range messages {
				for _, f := range tc.forbidden {
					require.NotContains(t, m, f)
				}
			}
		})
	}
}

func TestCyberArkFetch_FieldMissingFromResponse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "x"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc/Database")
	require.Error(t, err)
	require.Contains(t, err.Error(), `field "Database"`)
}

func TestCyberArkFetch_FieldEmptyInResponse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": ""})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestCyberArkFetch_Unauthorized(t *testing.T) {
	fake := &fakeCCP{accounts: map[string]map[string]any{}, missing: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/AIMWebService/api/Accounts", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"ErrorCode":"AUTH","ErrorMsg":"App not authorized"}`, http.StatusUnauthorized)
	})
	fake.Server = httptest.NewServer(mux)
	defer fake.Close()

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
	require.Contains(t, err.Error(), "App not authorized")
}

// testSelfSignedCAPEM is a syntactically-valid X.509 self-signed CA PEM block
// used purely to drive the CA-bundle parsing happy path. It is NOT used for
// any real TLS handshake.
const testSelfSignedCAPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

func TestCyberArkResolveBody_CacheHitAvoidsSecondHTTP(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})

	v1, err := c.resolveBody("Lab/Acc", "policy-a")
	require.NoError(t, err)
	require.Equal(t, "v1", v1)

	v2, err := c.resolveBody("Lab/Acc", "policy-b")
	require.NoError(t, err)
	require.Equal(t, "v1", v2)

	require.EqualValues(t, 1, fake.calls.Load(), "second resolve should hit cache")
}

func TestCyberArkSolvePolicySecrets_ReplacesPlaceholder(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "s3cret"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	payload := config.PolicyPayload{
		ID: "policy-1",
		Data: map[string]any{
			"auth": map[string]any{"password": "${cyberark://Lab/Acc}"},
		},
	}
	out, err := c.SolvePolicySecrets(payload)
	require.NoError(t, err)
	auth := out.Data.(map[string]any)["auth"].(map[string]any)
	require.Equal(t, "s3cret", auth["password"])
}

func TestCyberArkPollSecrets_DetectsChange(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	got := make(chan map[string]bool, 4)
	c.RegisterUpdatePoliciesCallback(func(m map[string]bool) { got <- m })

	_, err := c.resolveBody("Lab/Acc", "policy-1")
	require.NoError(t, err)

	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v2"})

	c.pollSecrets()
	select {
	case m := <-got:
		require.Equal(t, map[string]bool{"policy-1": true}, m)
	case <-time.After(time.Second):
		t.Fatal("expected change callback not invoked")
	}
}

func TestCyberArkPollSecrets_FailureEvictsAndReportsFalse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	got := make(chan map[string]bool, 4)
	c.RegisterUpdatePoliciesCallback(func(m map[string]bool) { got <- m })

	_, err := c.resolveBody("Lab/Acc", "policy-1")
	require.NoError(t, err)

	fake.delete("orb-agent", "Lab", "Acc")

	c.pollSecrets()
	select {
	case m := <-got:
		require.Equal(t, map[string]bool{"policy-1": false}, m)
	case <-time.After(time.Second):
		t.Fatal("expected failure callback not invoked")
	}

	c.mu.Lock()
	_, present := c.usedVars["Lab/Acc"]
	c.mu.Unlock()
	require.False(t, present, "failed entry must be evicted")
}

func TestNewManager_ReturnsCyberArkManagerWhenActive(t *testing.T) {
	logger := newTestLogger()
	m, err := New(logger, config.ManagerSecrets{
		Active: "cyberark",
		Sources: config.SecretsSources{
			CyberArk: config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb"},
		},
	})
	require.NoError(t, err)
	_, ok := m.(*cyberarkManager)
	require.True(t, ok, "New() with active=cyberark must return *cyberarkManager, got %T", m)
}

// generateTestCertPair produces a self-signed EC cert/key PEM pair valid for
// 127.0.0.1 and "localhost" with the given CommonName. Used to drive the
// mTLS round-trip test; not used in production paths.
func generateTestCertPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestCyberArk_mTLS_HandshakeRoundTrip(t *testing.T) {
	// Generate a CA-ish cert that doubles as a server cert AND is accepted
	// as a client cert. Same key material is used for both sides of the
	// handshake; this is fine for the test's purposes (it proves Go's
	// http.Client presents the cert we asked for).
	serverCertPEM, serverKeyPEM := generateTestCertPair(t, "server.localhost")
	clientCertPEM, clientKeyPEM := generateTestCertPair(t, "orb-agent-client")

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, serverCertPEM, 0o600))
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certFile, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, clientKeyPEM, 0o600))

	// Server requires client cert.
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	clientCA := x509.NewCertPool()
	clientCA.AppendCertsFromPEM(clientCertPEM)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Content":"mtls-ok"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// With a configured client cert + CA bundle, the handshake should succeed.
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:        srv.URL,
			AppID:      "orb-agent",
			CABundle:   caFile,
			ClientCert: certFile,
			ClientKey:  keyFile,
		},
	}
	require.NoError(t, c.Start(context.Background()))

	val, err := c.fetch("Lab/Acc")
	require.NoError(t, err)
	require.Equal(t, "mtls-ok", val)

	// Without the client cert/key, the handshake must fail.
	c2 := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:      srv.URL,
			AppID:    "orb-agent",
			CABundle: caFile,
		},
	}
	require.NoError(t, c2.Start(context.Background()))
	_, err = c2.fetch("Lab/Acc")
	require.Error(t, err, "fetch without client cert must fail")
}

func TestCyberArk_SkipTLSVerify_AcceptsSelfSignedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Content":"skip-tls-ok"}`))
	}))
	defer srv.Close()

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:           srv.URL,
			AppID:         "orb-agent",
			SkipTLSVerify: true,
		},
	}
	require.NoError(t, c.Start(context.Background()))

	val, err := c.fetch("Lab/Acc")
	require.NoError(t, err)
	require.Equal(t, "skip-tls-ok", val)
}
