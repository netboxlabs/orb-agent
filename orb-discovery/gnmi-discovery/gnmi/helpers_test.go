package gnmi

import (
	"context"
	"errors"
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// pathToString
// ---------------------------------------------------------------------------

func TestPathToString_NilPath(t *testing.T) {
	assert.Equal(t, "", pathToString(nil))
}

func TestPathToString_EmptyPath(t *testing.T) {
	assert.Equal(t, "", pathToString(&gnmiproto.Path{}))
}

func TestPathToString_SingleElemNoKeys(t *testing.T) {
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "interfaces"},
		},
	}
	assert.Equal(t, "/interfaces", pathToString(p))
}

func TestPathToString_MultipleElemsNoKeys(t *testing.T) {
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "interfaces"},
			{Name: "interface"},
			{Name: "state"},
		},
	}
	assert.Equal(t, "/interfaces/interface/state", pathToString(p))
}

// Older targets/proxies may populate the deprecated repeated Path.element
// instead of Path.elem; pathToString must fall back to it (each entry is an
// already-rendered element) rather than returning an empty path.
func TestPathToString_DeprecatedElementFallback(t *testing.T) {
	p := &gnmiproto.Path{
		Element: []string{"interfaces", "interface[name=eth0]", "state"},
	}
	assert.Equal(t, "/interfaces/interface[name=eth0]/state", pathToString(p))

	// When both are present, the modern Elem wins (no double-render).
	p2 := &gnmiproto.Path{
		Elem:    []*gnmiproto.PathElem{{Name: "system"}},
		Element: []string{"ignored"},
	}
	assert.Equal(t, "/system", pathToString(p2))
}

func TestPathToString_StripsModulePrefix(t *testing.T) {
	// Some targets (e.g. Nokia SR Linux on a JSON_IETF subscribe) render the
	// first element module-qualified. We normalize "module:name" to the bare
	// OpenConfig name so AllowsPath / profile matching works regardless.
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "openconfig-system:system"},
			{Name: "state"},
			{Name: "hostname"},
		},
	}
	assert.Equal(t, "/system/state/hostname", pathToString(p))

	// A module-qualified keyed element keeps its keys after the prefix strip.
	p2 := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "openconfig-interfaces:interfaces"},
			{Name: "interface", Key: map[string]string{"name": "ethernet-1/1"}},
		},
	}
	assert.Equal(t, "/interfaces/interface[name=ethernet-1/1]", pathToString(p2))
}

func TestPathToString_ElemWithSingleKey(t *testing.T) {
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
			{Name: "state"},
		},
	}
	assert.Equal(t, "/interfaces/interface[name=Ethernet1]/state", pathToString(p))
}

func TestPathToString_ElemWithMultipleKeysSorted(t *testing.T) {
	// Keys must be sorted alphabetically for deterministic output.
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "route", Key: map[string]string{"prefix": "10.0.0.0/8", "vrf": "default"}},
		},
	}
	// "prefix" sorts before "vrf"
	assert.Equal(t, "/route[prefix=10.0.0.0/8][vrf=default]", pathToString(p))
}

func TestPathToString_IPv6KeyValue(t *testing.T) {
	// IPv6 addresses and slashes inside key values must not confuse the builder.
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "addresses"},
			{Name: "address", Key: map[string]string{"ip": "2001:db8::1"}},
		},
	}
	assert.Equal(t, "/addresses/address[ip=2001:db8::1]", pathToString(p))
}

func TestPathToString_OriginNotRendered(t *testing.T) {
	// Origin field must be omitted from the rendered string.
	p := &gnmiproto.Path{
		Origin: "openconfig",
		Elem: []*gnmiproto.PathElem{
			{Name: "system"},
		},
	}
	assert.Equal(t, "/system", pathToString(p))
}

func TestPathToString_ElemWithNilKey(t *testing.T) {
	// Elem with an explicit nil key map — just the name should appear.
	p := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "bgp", Key: nil},
		},
	}
	assert.Equal(t, "/bgp", pathToString(p))
}

// ---------------------------------------------------------------------------
// joinPaths
// ---------------------------------------------------------------------------

func TestJoinPaths_BothEmpty(t *testing.T) {
	assert.Equal(t, "", joinPaths("", ""))
}

func TestJoinPaths_EmptyPrefix(t *testing.T) {
	assert.Equal(t, "/foo/bar", joinPaths("", "/foo/bar"))
}

func TestJoinPaths_EmptyPath(t *testing.T) {
	assert.Equal(t, "/foo", joinPaths("/foo", ""))
}

func TestJoinPaths_NoDoubleSlash(t *testing.T) {
	// prefix ends with slash, path starts with slash — must not produce "//".
	assert.Equal(t, "/prefix/leaf", joinPaths("/prefix/", "/leaf"))
}

func TestJoinPaths_NormalConcatenation(t *testing.T) {
	assert.Equal(t, "/interfaces/interface[name=eth0]/state", joinPaths("/interfaces", "/interface[name=eth0]/state"))
}

func TestJoinPaths_PrefixNoTrailingSlash(t *testing.T) {
	assert.Equal(t, "/a/b", joinPaths("/a", "/b"))
}

// ---------------------------------------------------------------------------
// decodeTypedValue
// ---------------------------------------------------------------------------

func TestDecodeTypedValue_Nil(t *testing.T) {
	assert.Nil(t, decodeTypedValue(nil))
}

func TestDecodeTypedValue_StringVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_StringVal{StringVal: "hello"}}
	assert.Equal(t, "hello", decodeTypedValue(tv))
}

func TestDecodeTypedValue_IntVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_IntVal{IntVal: -42}}
	result := decodeTypedValue(tv)
	v, ok := result.(int64)
	require.True(t, ok, "expected int64, got %T", result)
	assert.Equal(t, int64(-42), v)
}

func TestDecodeTypedValue_UintVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_UintVal{UintVal: 1000}}
	result := decodeTypedValue(tv)
	v, ok := result.(uint64)
	require.True(t, ok, "expected uint64, got %T", result)
	assert.Equal(t, uint64(1000), v)
}

func TestDecodeTypedValue_LeaflistVal(t *testing.T) {
	// A native leaf-list (e.g. trunk-vlans when a target ignores json_ietf) must
	// decode to []any of the per-element values, so leaf-list consumers see the
	// same shape as the JSON_IETF array encoding.
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_LeaflistVal{
		LeaflistVal: &gnmiproto.ScalarArray{Element: []*gnmiproto.TypedValue{
			{Value: &gnmiproto.TypedValue_UintVal{UintVal: 20}},
			{Value: &gnmiproto.TypedValue_StringVal{StringVal: "30..32"}},
		}},
	}}
	result := decodeTypedValue(tv)
	arr, ok := result.([]any)
	require.True(t, ok, "expected []any, got %T", result)
	require.Len(t, arr, 2)
	assert.Equal(t, uint64(20), arr[0])
	assert.Equal(t, "30..32", arr[1])
}

func TestDecodeTypedValue_BoolVal_True(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_BoolVal{BoolVal: true}}
	assert.Equal(t, true, decodeTypedValue(tv))
}

func TestDecodeTypedValue_BoolVal_False(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_BoolVal{BoolVal: false}}
	assert.Equal(t, false, decodeTypedValue(tv))
}

func TestDecodeTypedValue_DoubleVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_DoubleVal{DoubleVal: 3.14}}
	result := decodeTypedValue(tv)
	v, ok := result.(float64)
	require.True(t, ok, "expected float64, got %T", result)
	assert.InDelta(t, 3.14, v, 1e-9)
}

func TestDecodeTypedValue_BytesVal(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_BytesVal{BytesVal: data}}
	assert.Equal(t, data, decodeTypedValue(tv))
}

func TestDecodeTypedValue_AsciiVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_AsciiVal{AsciiVal: "raw-ascii"}}
	assert.Equal(t, "raw-ascii", decodeTypedValue(tv))
}

func TestDecodeTypedValue_JsonIetfVal_Number(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`42`)}}
	result := decodeTypedValue(tv)
	// json.Unmarshal decodes numbers as float64 by default.
	v, ok := result.(float64)
	require.True(t, ok, "expected float64, got %T", result)
	assert.Equal(t, float64(42), v)
}

func TestDecodeTypedValue_JsonIetfVal_String(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`"arista"`)}}
	assert.Equal(t, "arista", decodeTypedValue(tv))
}

func TestDecodeTypedValue_JsonIetfVal_Bool(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`true`)}}
	assert.Equal(t, true, decodeTypedValue(tv))
}

func TestDecodeTypedValue_JsonIetfVal_Object(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`{"oper-status":"UP"}`)}}
	result := decodeTypedValue(tv)
	m, ok := result.(map[string]any)
	require.True(t, ok, "expected map, got %T", result)
	assert.Equal(t, "UP", m["oper-status"])
}

func TestDecodeTypedValue_JsonIetfVal_InvalidJSON_FallsBackToString(t *testing.T) {
	raw := []byte(`not-json`)
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: raw}}
	assert.Equal(t, "not-json", decodeTypedValue(tv))
}

func TestDecodeTypedValue_JsonVal_Valid(t *testing.T) {
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonVal{JsonVal: []byte(`{"mtu":9000}`)}}
	result := decodeTypedValue(tv)
	m, ok := result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(9000), m["mtu"])
}

func TestDecodeTypedValue_JsonVal_InvalidJSON_FallsBackToString(t *testing.T) {
	raw := []byte(`{bad}`)
	tv := &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonVal{JsonVal: raw}}
	assert.Equal(t, "{bad}", decodeTypedValue(tv))
}

// ---------------------------------------------------------------------------
// convertNotification
// ---------------------------------------------------------------------------

func TestConvertNotification_Nil(t *testing.T) {
	n := convertNotification(nil)
	assert.Empty(t, n.Updates)
	assert.Empty(t, n.Deletes)
}

func TestConvertNotification_NoPrefix(t *testing.T) {
	proto := &gnmiproto.Notification{
		Update: []*gnmiproto.Update{
			{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "system"}, {Name: "state"}, {Name: "hostname"}}},
				Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_StringVal{StringVal: "spine1"}},
			},
		},
	}
	n := convertNotification(proto)
	require.Len(t, n.Updates, 1)
	assert.Equal(t, "/system/state/hostname", n.Updates[0].Path)
	assert.Equal(t, "spine1", n.Updates[0].Value)
	assert.Empty(t, n.Deletes)
}

func TestConvertNotification_WithPrefix(t *testing.T) {
	prefix := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": "Ethernet1"}},
		},
	}
	proto := &gnmiproto.Notification{
		Prefix: prefix,
		Update: []*gnmiproto.Update{
			{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "state"}, {Name: "oper-status"}}},
				Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_StringVal{StringVal: "UP"}},
			},
		},
	}
	n := convertNotification(proto)
	require.Len(t, n.Updates, 1)
	assert.Equal(t, "/interfaces/interface[name=Ethernet1]/state/oper-status", n.Updates[0].Path)
	assert.Equal(t, "UP", n.Updates[0].Value)
}

func TestConvertNotification_WithDeletes(t *testing.T) {
	prefix := &gnmiproto.Path{
		Elem: []*gnmiproto.PathElem{{Name: "network-instances"}},
	}
	proto := &gnmiproto.Notification{
		Prefix: prefix,
		Delete: []*gnmiproto.Path{
			{Elem: []*gnmiproto.PathElem{{Name: "network-instance", Key: map[string]string{"name": "VRF-A"}}}},
		},
	}
	n := convertNotification(proto)
	assert.Empty(t, n.Updates)
	require.Len(t, n.Deletes, 1)
	assert.Equal(t, "/network-instances/network-instance[name=VRF-A]", n.Deletes[0])
}

func TestConvertNotification_MultipleUpdatesAndDeletes(t *testing.T) {
	proto := &gnmiproto.Notification{
		Update: []*gnmiproto.Update{
			{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "a"}}},
				Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_IntVal{IntVal: 1}},
			},
			{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "b"}}},
				Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_IntVal{IntVal: 2}},
			},
		},
		Delete: []*gnmiproto.Path{
			{Elem: []*gnmiproto.PathElem{{Name: "x"}}},
			{Elem: []*gnmiproto.PathElem{{Name: "y"}}},
		},
	}
	n := convertNotification(proto)
	assert.Len(t, n.Updates, 2)
	assert.Len(t, n.Deletes, 2)
	assert.Equal(t, "/a", n.Updates[0].Path)
	assert.Equal(t, "/b", n.Updates[1].Path)
	assert.Equal(t, "/x", n.Deletes[0])
	assert.Equal(t, "/y", n.Deletes[1])
}

func TestConvertNotification_NilVal_DecodesAsNil(t *testing.T) {
	proto := &gnmiproto.Notification{
		Update: []*gnmiproto.Update{
			{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "leaf"}}},
				Val:  nil,
			},
		},
	}
	n := convertNotification(proto)
	require.Len(t, n.Updates, 1)
	assert.Nil(t, n.Updates[0].Value)
}

// ---------------------------------------------------------------------------
// mapCapabilities
// ---------------------------------------------------------------------------

func TestMapCapabilities_EmptyResponse(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{}
	result := mapCapabilities(resp)
	assert.Equal(t, "", result.Vendor)
	assert.Empty(t, result.Models)
	assert.Empty(t, result.Encodings)
}

func TestMapCapabilities_KnownVendorArista(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "openconfig-interfaces", Organization: "OpenConfig working group"},
			{Name: "arista-eos-bgp", Organization: "Arista Networks"},
		},
		SupportedEncodings: []gnmiproto.Encoding{gnmiproto.Encoding_JSON_IETF},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Arista", result.Vendor)
	assert.Equal(t, []string{"openconfig-interfaces", "arista-eos-bgp"}, result.Models)
	assert.Equal(t, []string{"JSON_IETF"}, result.Encodings)
}

func TestMapCapabilities_KnownVendorCisco(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "Cisco-IOS-XR-ifmgr-cfg", Organization: "Cisco Systems, Inc."},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Cisco", result.Vendor)
}

func TestMapCapabilities_KnownVendorNokia(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "nokia-conf", Organization: "Nokia"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Nokia", result.Vendor)
}

func TestMapCapabilities_KnownVendorJuniper(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "junos-conf-root", Organization: "Juniper Networks, Inc."},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Juniper", result.Vendor)
}

func TestMapCapabilities_KnownVendorNVIDIA(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "nvidia-bgp", Organization: "NVIDIA Corporation"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "NVIDIA", result.Vendor)
}

func TestMapCapabilities_CumulusTokenRecognized(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "cumulus-bgp", Organization: "Cumulus Networks"},
		},
	}
	result := mapCapabilities(resp)
	// The cumulus token resolves to the NVIDIA manufacturer (Cumulus is
	// NVIDIA's NOS, not a NetBox manufacturer of its own).
	assert.Equal(t, "NVIDIA", result.Vendor)
}

func TestMapCapabilities_MellanoxTokenRecognized(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "mellanox-interfaces", Organization: "Mellanox Technologies"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Mellanox", result.Vendor)
}

func TestMapCapabilities_HuaweiTokenRecognized(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "huawei-bgp", Organization: "Huawei Technologies Co., Ltd."},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Huawei", result.Vendor)
}

func TestMapCapabilities_UnknownVendorNoFallback(t *testing.T) {
	// Unknown organization must NOT surface as Vendor — keeps it empty.
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "openconfig-interfaces", Organization: "OpenConfig working group"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "", result.Vendor)
	assert.Equal(t, []string{"openconfig-interfaces"}, result.Models)
}

func TestMapCapabilities_FirstMatchWins(t *testing.T) {
	// arista appears before juniper in vendorTokenOrder — arista must win.
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "model-a", Organization: "Arista Networks"},
			{Name: "model-j", Organization: "Juniper Networks"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Arista", result.Vendor)
}

func TestMapCapabilities_MultipleEncodings(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedEncodings: []gnmiproto.Encoding{
			gnmiproto.Encoding_JSON,
			gnmiproto.Encoding_JSON_IETF,
			gnmiproto.Encoding_PROTO,
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, []string{"JSON", "JSON_IETF", "PROTO"}, result.Encodings)
}

// ---------------------------------------------------------------------------
// FakeSession — covering fake.go scaffolding within gnmi package
// ---------------------------------------------------------------------------

func TestFakeSession_CapabilitiesSuccess(t *testing.T) {
	caps := &CapabilitiesResult{Vendor: "Arista", Models: []string{"oc-bgp"}, Encodings: []string{"JSON_IETF"}}
	f := &FakeSession{Caps: caps}
	got, err := f.Capabilities(context.Background())
	require.NoError(t, err)
	assert.Equal(t, caps, got)
}

func TestFakeSession_CapabilitiesError(t *testing.T) {
	sentinel := errors.New("caps rpc failed")
	f := &FakeSession{CapsErr: sentinel}
	got, err := f.Capabilities(context.Background())
	assert.Nil(t, got)
	assert.ErrorIs(t, err, sentinel)
}

func TestFakeSession_GetOnceSuccess(t *testing.T) {
	result := Notification{Updates: []Update{{Path: "/system/hostname", Value: "leaf1"}}, SyncDone: true}
	f := &FakeSession{GetResult: result}
	got, err := f.GetOnce(context.Background(), []string{"/system"})
	require.NoError(t, err)
	assert.Equal(t, result, got)
}

func TestFakeSession_GetOnceError(t *testing.T) {
	sentinel := errors.New("get failed")
	f := &FakeSession{GetErr: sentinel}
	_, err := f.GetOnce(context.Background(), nil)
	assert.ErrorIs(t, err, sentinel)
}

func TestFakeSession_Close(t *testing.T) {
	f := &FakeSession{}
	assert.False(t, f.Closed)
	err := f.Close()
	require.NoError(t, err)
	assert.True(t, f.Closed)
}

func TestFakeSession_SubscribeSample_ReceivesNotifications(t *testing.T) {
	snap := []Notification{
		{Updates: []Update{{Path: "/interfaces/interface[name=eth0]/state/oper-status", Value: "UP"}}},
		{SyncDone: true},
	}
	f := &FakeSession{SampleSnapshots: snap}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notes, _, err := f.Subscribe(ctx, Sample, []string{"/interfaces"}, 0)
	require.NoError(t, err)
	first := <-notes
	require.Len(t, first.Updates, 1)
	assert.Equal(t, "UP", first.Updates[0].Value)
	second := <-notes
	assert.True(t, second.SyncDone)
}

func TestFakeSession_SubscribeOnChange_StreamError(t *testing.T) {
	sentinel := errors.New("stream dropped")
	f := &FakeSession{
		OnChangeSupport: true,
		OnChangeStream:  []Notification{{SyncDone: true}},
		StreamErr:       sentinel,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notes, errs, err := f.Subscribe(ctx, OnChange, nil, 0)
	require.NoError(t, err)
	// drain the stream notification
	<-notes
	// the error must arrive on the error channel
	got := <-errs
	assert.ErrorIs(t, got, sentinel)
}

// ---------------------------------------------------------------------------
// FakeDialer — covering Dial within gnmi package
// ---------------------------------------------------------------------------

func TestFakeDialer_DialReturnsSession(t *testing.T) {
	sess := &FakeSession{Caps: &CapabilitiesResult{Vendor: "Nokia"}}
	d := &FakeDialer{Session: sess}
	got, err := d.Dial(context.Background(), TargetSpec{Host: "192.0.2.1:57400"})
	require.NoError(t, err)
	assert.Equal(t, sess, got)
}

func TestMapCapabilities_KnownVendorDell(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "dell-system", Organization: "Dell Inc."},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Dell", result.Vendor)
}

// SONiC is a network OS, not a hardware vendor: it sets NOS (which biases
// profile selection) and leaves Vendor empty (so it never becomes a manufacturer).
func TestMapCapabilities_KnownVendorSONiC(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "sonic-system", Organization: "SONiC"},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "", result.Vendor, "SONiC must not be a manufacturer")
	assert.Equal(t, "SONiC", result.NOS)
}

// A Dell-built SONiC box advertises both tokens. The hardware vendor (Dell) and
// the NOS (SONiC) are detected on independent scans: Vendor=Dell drives the
// manufacturer, NOS=SONiC biases profile selection toward the sonic overlay.
func TestMapCapabilities_DellSonicSeparateSignals(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{
		SupportedModels: []*gnmiproto.ModelData{
			{Name: "openconfig-interfaces", Organization: "OpenConfig working group"},
			{Name: "sonic-port", Organization: "SONiC"},
			{Name: "dell-platform", Organization: "Dell Inc."},
		},
	}
	result := mapCapabilities(resp)
	assert.Equal(t, "Dell", result.Vendor)
	assert.Equal(t, "SONiC", result.NOS)
}

func TestNegotiateEncoding(t *testing.T) {
	// JSON_IETF preferred when advertised.
	assert.Equal(t, "json_ietf", negotiateEncoding([]string{"JSON", "JSON_IETF", "PROTO"}))
	assert.Equal(t, "json_ietf", negotiateEncoding([]string{"JSON_IETF"}))
	// JSON-only target (e.g. NX-OS) -> json.
	assert.Equal(t, "json", negotiateEncoding([]string{"JSON", "PROTO"}))
	// Nothing usable advertised (or empty) -> best-effort json_ietf default.
	assert.Equal(t, "json_ietf", negotiateEncoding([]string{"PROTO", "BYTES"}))
	assert.Equal(t, "json_ietf", negotiateEncoding(nil))
}

func TestNegotiateSubEncoding(t *testing.T) {
	// PROTO preferred for Subscribe whenever advertised — a JSON_IETF stream
	// serializes leaves as nested container subtrees our flat-leaf model can't
	// match, while PROTO yields one flat scalar update per leaf.
	assert.Equal(t, "proto", negotiateSubEncoding([]string{"JSON_IETF", "PROTO"}))
	assert.Equal(t, "proto", negotiateSubEncoding([]string{"proto"}))
	// No PROTO advertised -> fall back to the Get encoding negotiation.
	assert.Equal(t, "json_ietf", negotiateSubEncoding([]string{"JSON_IETF"}))
	assert.Equal(t, "json", negotiateSubEncoding([]string{"JSON"}))
	assert.Equal(t, "json_ietf", negotiateSubEncoding(nil))
}

func TestSubEnc_FallsBackToGetEncoding(t *testing.T) {
	// Unset subEncoding falls back to enc() (json_ietf default), not "".
	s := &gnmicSession{}
	assert.Equal(t, "json_ietf", s.subEnc())
	s.encoding = "json"
	assert.Equal(t, "json", s.subEnc()) // still no PROTO negotiated -> Get encoding
	s.subEncoding = "proto"
	assert.Equal(t, "proto", s.subEnc())
}

func TestWithOrigin(t *testing.T) {
	assert.Equal(t, "openconfig:/system/state/hostname", withOrigin("openconfig", "/system/state/hostname"))
	assert.Equal(t, "/system/state/hostname", withOrigin("", "/system/state/hostname")) // origin-less
	assert.Equal(t, "oc:/interfaces", withOrigin("oc", "/interfaces"))
}
