package secretsmgr

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

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

func TestCyberArkStart_TrimsTrailingSlashFromURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com/", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, "https://ccp.example.com", c.baseURL)
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
