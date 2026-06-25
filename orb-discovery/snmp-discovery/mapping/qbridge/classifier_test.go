package qbridge

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		in   SwitchportInfo
		want Classification
	}{
		{
			name: "disabled port -> ModeUnknown",
			in: SwitchportInfo{
				Enabled:           false,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(10),
			},
			want: Classification{Mode: ModeUnknown, Tagged: []int{}, Untagged: nil},
		},
		{
			name: "absent from bridge table -> ModeUnknown",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: false,
			},
			want: Classification{Mode: ModeUnknown, Tagged: []int{}, Untagged: nil},
		},
		{
			name: "operational routed -> ModeRouted",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				OperMode:          OperRouted,
			},
			want: Classification{Mode: ModeRouted, Tagged: []int{}, Untagged: nil},
		},
		{
			name: "access mode, no voice",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(10),
			},
			want: Classification{Mode: ModeAccess, Tagged: []int{}, Untagged: intPtr(10)},
		},
		{
			name: "access + voice promoted to trunk",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(10),
				VoiceVlan:         intPtr(100),
			},
			want: Classification{Mode: ModeTrunk, Tagged: []int{100}, Untagged: intPtr(10)},
		},
		{
			name: "access + voice == access -> stays access",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(10),
				VoiceVlan:         intPtr(10),
			},
			want: Classification{Mode: ModeAccess, Tagged: []int{}, Untagged: intPtr(10)},
		},
		{
			name: "trunk with explicit allowed list",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				NativeVlan:        intPtr(1),
				AllowedVlans:      AllowedVlans{Vids: []int{1, 10, 20}},
			},
			want: Classification{Mode: ModeTrunk, Tagged: []int{10, 20}, Untagged: intPtr(1)},
		},
		{
			name: "trunk with wildcard -> ModeTrunkAll",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				NativeVlan:        intPtr(1),
				AllowedVlans:      AllowedVlans{IsWildcard: true},
			},
			want: Classification{Mode: ModeTrunkAll, Tagged: []int{}, Untagged: intPtr(1)},
		},
		{
			name: "dynamic admin falls back to oper access",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminDynamic,
				OperMode:          OperAccess,
				AccessVlan:        intPtr(20),
			},
			want: Classification{Mode: ModeAccess, Tagged: []int{}, Untagged: intPtr(20)},
		},
		{
			name: "dynamic admin falls back to oper trunk",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminDynamic,
				OperMode:          OperTrunk,
				NativeVlan:        intPtr(99),
				AllowedVlans:      AllowedVlans{Vids: []int{99, 100}},
			},
			want: Classification{Mode: ModeTrunk, Tagged: []int{100}, Untagged: intPtr(99)},
		},
		{
			name: "dynamic admin + unknown oper -> ModeUnknown",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminDynamic,
				OperMode:          OperUnknown,
			},
			want: Classification{Mode: ModeUnknown, Tagged: []int{}, Untagged: nil},
		},
		{
			name: "voice on trunk port is ignored (no double-tagging)",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				NativeVlan:        intPtr(1),
				AllowedVlans:      AllowedVlans{Vids: []int{1, 10}},
				VoiceVlan:         intPtr(100),
			},
			want: Classification{Mode: ModeTrunk, Tagged: []int{10}, Untagged: intPtr(1)},
		},
		{
			name: "trunk dedupes native from tagged",
			in: SwitchportInfo{
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				NativeVlan:        intPtr(50),
				AllowedVlans:      AllowedVlans{Vids: []int{10, 50, 60}},
			},
			want: Classification{Mode: ModeTrunk, Tagged: []int{10, 60}, Untagged: intPtr(50)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.in)
			if !equalClassification(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func equalClassification(a, b Classification) bool {
	if a.Mode != b.Mode {
		return false
	}
	if !reflect.DeepEqual(a.Tagged, b.Tagged) {
		return false
	}
	if (a.Untagged == nil) != (b.Untagged == nil) {
		return false
	}
	if a.Untagged != nil && *a.Untagged != *b.Untagged {
		return false
	}
	return true
}
