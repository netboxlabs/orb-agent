package policy

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

const guardHost = "192.0.2.20:57400"

// noHostname makes guardRunner's device report no hostname leaf at all.
const noHostname = "\x00"

// guardRunner polls a GET target whose hostname leaf is hostname, with one
// interface carrying the target's address so the primary IP is set too.
func guardRunner(t *testing.T, hostname string, netboxID *int) (*Runner, *recordingClient, *syncBuf) {
	t.Helper()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	updates := []gnmi.Update{
		{Path: "/interfaces/interface[name=Ethernet1]/state/type", Value: "iana-if-type:ethernetCsmacd"},
		{Path: "/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=192.0.2.20]/state/prefix-length", Value: float64(24)},
	}
	if hostname != noHostname {
		updates = append(updates, gnmi.Update{Path: "/system/state/hostname", Value: hostname})
	}
	fake := &gnmi.FakeSession{GetResult: gnmi.Notification{Updates: updates}}
	client := &recordingClient{}
	logs := &syncBuf{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeGet, GetIntervalMs: 20, DebounceMs: 10,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: guardHost, NetboxID: netboxID}}},
	}
	r, err := NewRunner(context.Background(), slog.New(slog.NewTextHandler(logs, nil)),
		"p1", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { require.NoError(t, r.Stop()) })
	return r, client, logs
}

// deviceNames returns every device name the payload carries, nested ones included.
func deviceNames(ents []diode.Entity) []string {
	var out []string
	add := func(d *diode.Device) {
		if d != nil && d.Name != nil {
			out = append(out, *d.Name)
		}
	}
	for _, e := range ents {
		switch v := e.(type) {
		case *diode.Device:
			add(v)
			for _, ip := range []*diode.IPAddress{v.PrimaryIp4, v.PrimaryIp6} {
				if ip != nil {
					if i, ok := ip.AssignedObject.(*diode.Interface); ok {
						add(i.Device)
					}
				}
			}
		case *diode.Interface:
			add(v.Device)
		case *diode.IPAddress:
			if i, ok := v.AssignedObject.(*diode.Interface); ok {
				add(i.Device)
			}
		}
	}
	return out
}

// A hostname of only spaces is no identity: without a netbox_id there is nothing
// to match the device on, and NetBox would get a device named "   ".
func TestWhitespaceHostnameWithoutNetboxIDIsNotIngested(t *testing.T) {
	_, client, logs := guardRunner(t, "   ", nil)

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "skipping flush: no device identity")
	}, 2*time.Second, 10*time.Millisecond)
	require.Zero(t, client.count())
}

// With a netbox_id the device is matched by it, so it ingests, but without the
// blank name: sending it would rename the matched device.
func TestWhitespaceHostnameWithNetboxIDIsIngestedWithoutName(t *testing.T) {
	id := 7
	_, client, _ := guardRunner(t, "   ", &id)

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 10*time.Millisecond)
	ents := client.lastIngested()
	dev, ok := ents[0].(*diode.Device)
	require.True(t, ok)
	require.Nil(t, dev.Name)
	require.NotNil(t, dev.PrimaryIp4, "the primary IP is still set")
	require.Empty(t, deviceNames(ents), "no reference carries the blank name either")
}

// A real name is sent exactly as the device reports it.
func TestPaddedHostnameIsSentUnchanged(t *testing.T) {
	_, client, _ := guardRunner(t, " sw1 ", nil)

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 10*time.Millisecond)
	dev, ok := client.lastIngested()[0].(*diode.Device)
	require.True(t, ok)
	require.NotNil(t, dev.Name)
	require.Equal(t, " sw1 ", *dev.Name)
}

// primaryIPDevice is the device copy nested in the Device's primary IP.
func primaryIPDevice(t *testing.T, dev *diode.Device) *diode.Device {
	t.Helper()
	require.NotNil(t, dev.PrimaryIp4)
	iface, ok := dev.PrimaryIp4.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.NotNil(t, iface.Device)
	return iface.Device
}

// A device matched by netbox_id alone, with no usable hostname, can still be
// matched where it is nested in its primary IP: the copy there carries the
// same source_match, and nothing else from the Device's metadata.
func TestPrimaryIPDeviceCarriesSourceMatchWithoutAName(t *testing.T) {
	for name, hostname := range map[string]string{"absent": noHostname, "empty": "", "blank": "   "} {
		t.Run(name, func(t *testing.T) {
			id := 7
			_, client, _ := guardRunner(t, hostname, &id)

			require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 10*time.Millisecond)
			ents := client.lastIngested()
			dev, ok := ents[0].(*diode.Device)
			require.True(t, ok)
			require.Nil(t, dev.Name)
			nested := primaryIPDevice(t, dev)
			require.Nil(t, nested.Name)
			require.Equal(t, diode.Metadata{"source_match": diode.Metadata{"netbox_id": 7}}, nested.Metadata)
			require.Contains(t, dev.Metadata, "run_id", "the Device's own metadata is not shared with the copy")
		})
	}
}
