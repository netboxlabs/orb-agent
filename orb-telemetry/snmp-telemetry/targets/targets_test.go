package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpand_SingleIP(t *testing.T) {
	ips, err := Expand("192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, ips)
}

func TestExpand_Hostname(t *testing.T) {
	ips, err := Expand("example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, ips)
}

func TestExpand_HostnameWithHyphen(t *testing.T) {
	ips, err := Expand("my-router.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"my-router.example.com"}, ips)
}

func TestExpand_CIDR_Slash30(t *testing.T) {
	ips, err := Expand("10.0.0.0/30")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, ips)
}

func TestExpand_CIDR_Slash32(t *testing.T) {
	ips, err := Expand("10.0.0.5/32")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5"}, ips)
}

func TestExpand_CIDR_InvalidFormat(t *testing.T) {
	_, err := Expand("999.0.0.0/24")
	assert.Error(t, err)
}

func TestExpand_CIDR_IPv6Rejected(t *testing.T) {
	_, err := Expand("2001:db8::/32")
	assert.Error(t, err)
}

func TestExpand_LastOctetRange(t *testing.T) {
	ips, err := Expand("10.0.0.5-7")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}, ips)
}

func TestExpand_LastOctetRange_Single(t *testing.T) {
	ips, err := Expand("10.0.0.10-10")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.10"}, ips)
}

func TestExpand_LastOctetRange_EndBeforeStart(t *testing.T) {
	_, err := Expand("10.0.0.10-5")
	assert.Error(t, err)
}

func TestExpand_FullIPRange(t *testing.T) {
	ips, err := Expand("10.0.0.1-10.0.0.3")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, ips)
}

func TestExpand_FullIPRange_EndBeforeStart(t *testing.T) {
	_, err := Expand("10.0.0.10-10.0.0.5")
	assert.Error(t, err)
}

func TestExpand_FullIPRange_SameStartEnd(t *testing.T) {
	ips, err := Expand("192.168.0.1-192.168.0.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.0.1"}, ips)
}
