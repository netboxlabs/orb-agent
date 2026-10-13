package mapping

import (
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// descriptionMaxLen is NetBox's limit for description fields, in characters.
const descriptionMaxLen = 200

// truncateText cuts s to at most maxLen characters, ending in "..." when it
// had to cut. It counts characters rather than bytes, as NetBox does, so it
// never splits a multi-byte character into invalid UTF-8.
func truncateText(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	kept := 0
	for i := range s {
		if kept == maxLen-3 {
			return s[:i] + "..."
		}
		kept++
	}
	return s
}

// InvalidUTF8Warning is logged for each free-text field RepairInvalidUTF8
// repaired.
const InvalidUTF8Warning = "device text is not valid UTF-8; the invalid bytes were replaced " +
	"with U+FFFD so the batch can be ingested; set the value in UTF-8 on the device to send it as written"

// InvalidUTF8Refusal is logged for each field RepairInvalidUTF8 refused.
const InvalidUTF8Refusal = "device text is not valid UTF-8 in a field that is not free text, such as " +
	"a name or serial that records are identified by; the target is not ingested, because a replaced " +
	"value there could tie it to a different record or store a wrong identifier; set the value in " +
	"UTF-8 on the device"

// Repair reports the invalid UTF-8 found in one field of one entity type.
type Repair struct {
	Entity  string // Diode entity type, such as "Interface"
	Field   string
	Count   int
	Example string // the first value found, invalid bytes escaped as \xNN
}

// RepairInvalidUTF8 finds every string reachable from entities that is not
// valid UTF-8, which protobuf refuses to marshal and which would fail the
// whole ingest batch. In free-text fields it replaces each run of invalid
// bytes with U+FFFD, in place, and reports the field as repaired. Any other
// field identifies a record: in a name Diode matches on, two different values
// can repair to the same text and tie two records together, and a repaired
// serial would be stored wrong. Those are left unchanged and reported as
// refused.
func RepairInvalidUTF8(entities []diode.Entity) (repaired, refused []Repair) {
	w := utf8Walker{
		seen:     map[visited]bool{},
		repaired: repairLog{index: map[repairKey]int{}},
		refused:  repairLog{index: map[repairKey]int{}},
	}
	w.walk(reflect.ValueOf(entities), "", "")
	return w.repaired.list, w.refused.list
}

// freeText reports whether a field is text that no Diode matcher or NetBox
// uniqueness rule reads. Names, models and slugs are all matched on,
// including VLAN names, which NetBox keeps unique within a VLAN group.
func freeText(entity, field string) bool {
	switch field {
	case "Description", "Label":
		return true
	case "Comments":
		return entity != "JournalEntry" // matched on its comments
	}
	return false
}

type visited struct {
	typ reflect.Type
	ptr uintptr
}

type repairKey struct{ entity, field string }

type repairLog struct {
	index map[repairKey]int
	list  []Repair
}

func (l *repairLog) add(entity, field, value string) {
	key := repairKey{entity, field}
	if i, ok := l.index[key]; ok {
		l.list[i].Count++
		return
	}
	quoted := strconv.Quote(value)
	l.index[key] = len(l.list)
	l.list = append(l.list, Repair{Entity: entity, Field: field, Count: 1, Example: quoted[1 : len(quoted)-1]})
}

type utf8Walker struct {
	seen     map[visited]bool
	repaired repairLog
	refused  repairLog
}

// walk visits v, which was read from field of a struct of type owner. Each
// pointer is visited once, so a VLAN shared by many interfaces is counted
// once and a reference cycle ends.
func (w *utf8Walker) walk(v reflect.Value, owner, field string) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		key := visited{v.Type(), v.Pointer()}
		if w.seen[key] {
			return
		}
		w.seen[key] = true
		w.walk(v.Elem(), owner, field)
	case reflect.Interface:
		if !v.IsNil() {
			w.walk(v.Elem(), owner, field)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			if t.Field(i).IsExported() {
				w.walk(v.Field(i), t.Name(), t.Field(i).Name)
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // bytes, not text
		}
		for i := range v.Len() {
			w.walk(v.Index(i), owner, field)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			w.walk(iter.Key(), owner, field)
			w.walk(iter.Value(), owner, field)
		}
	case reflect.String:
		s := v.String()
		if utf8.ValidString(s) {
			return
		}
		if freeText(owner, field) && v.CanSet() {
			v.SetString(strings.ToValidUTF8(s, "�"))
			w.repaired.add(owner, field, s)
			return
		}
		w.refused.add(owner, field, s)
	default:
	}
}
