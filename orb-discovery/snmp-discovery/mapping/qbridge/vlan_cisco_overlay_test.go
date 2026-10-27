package qbridge

import (
	"reflect"
	"testing"
)

func TestApplyCiscoTrunks(t *testing.T) {
	t.Run("complete trunk with native VLAN", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			IfAdminStatus:     map[int]int{100: 1},
			NativeVlan:        map[int]int{100: 1},
			ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 1, 610, 702)},
			ActiveSecond2k:    map[int][]byte{100: ciscoTestBitmap(2048, 3752)},
		}

		ApplyCiscoTrunks(infos, rows)
		got := Classify(*infos[100])

		if got.Mode != ModeTrunk {
			t.Fatalf("mode = %v, want trunk", got.Mode)
		}
		if !reflect.DeepEqual(got.Tagged, []int{610, 702, 3752}) {
			t.Errorf("tagged = %v", got.Tagged)
		}
		if got.Untagged == nil || *got.Untagged != 1 {
			t.Errorf("native = %v, want 1", got.Untagged)
		}
	})

	t.Run("incomplete bitmap preserves generic trunk", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{
			100: {
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				AllowedVlans:      AllowedVlans{Vids: []int{48, 791}},
			},
		}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 610)},
		}

		ApplyCiscoTrunks(infos, rows)

		if !reflect.DeepEqual(infos[100].AllowedVlans.Vids, []int{48, 791}) {
			t.Errorf("generic membership overwritten: %v", infos[100].AllowedVlans.Vids)
		}
	})

	t.Run("access port unchanged", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{
			100: {
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(3752),
			},
		}
		rows := CiscoRows{
			TrunkStatus:    map[int]int{100: 2},
			ActiveFirst2k:  map[int][]byte{100: ciscoTestBitmap(0, 610)},
			ActiveSecond2k: map[int][]byte{100: ciscoTestBitmap(2048, 3752)},
		}

		ApplyCiscoTrunks(infos, rows)
		got := Classify(*infos[100])

		if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 3752 {
			t.Errorf("access classification changed: %+v", got)
		}
	})

	t.Run("missing IF-MIB state does not create port", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 610)},
			ActiveSecond2k:    map[int][]byte{100: ciscoTestBitmap(2048, 3752)},
		}

		ApplyCiscoTrunks(infos, rows)
		if _, exists := infos[100]; exists {
			t.Fatal("created port without IF-MIB administrative state")
		}
	})
}
