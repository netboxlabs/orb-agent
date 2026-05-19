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
