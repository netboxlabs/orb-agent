package profiles

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// StringOrSlice unmarshals either a scalar YAML string or a sequence of strings.
// ktranslate profiles use both forms for the sysobjectid field.
type StringOrSlice []string

// UnmarshalYAML implements yaml.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value != "" {
			*s = StringOrSlice{value.Value}
		}
		return nil
	case yaml.SequenceNode:
		var items []string
		if err := value.Decode(&items); err != nil {
			return err
		}
		*s = items
		return nil
	}
	return fmt.Errorf("unsupported YAML node kind %v for StringOrSlice", value.Kind)
}

// Origin records where a profile was read from. It decides the winner when a
// bundled profile and an override file claim the same sysObjectID.
type Origin string

const (
	// OriginEmbedded marks a profile bundled into the binary.
	OriginEmbedded Origin = "embedded"
	// OriginOverride marks a profile read from an override directory.
	OriginOverride Origin = "override"
)

// Profile is the top-level representation of a ktranslate-compatible SNMP profile file.
type Profile struct {
	// FileName is the base filename, populated by the Loader (not from YAML).
	// It is what an `extends` or `matches` reference names.
	FileName string `yaml:"-"`
	// RelPath is the path relative to the profile root, populated by the Loader.
	// It is what an override file must match to replace a bundled profile.
	RelPath string `yaml:"-"`
	// Origin is where the profile was read from, populated by the Loader.
	Origin Origin `yaml:"-"`
	// ReplacesBundled is true when this profile came from the override
	// directory at a bundled profile's relative path, so it stands in for that
	// profile instead of adding one. Populated by the Loader.
	ReplacesBundled bool `yaml:"-"`

	Extends     []string          `yaml:"extends"`
	Provider    string            `yaml:"provider"`
	SysObjectID StringOrSlice     `yaml:"sysobjectid"`
	Matches     map[string]string `yaml:"matches"`
	// NoUseBulkWalkAll marks an agent that answers GETBULK badly or not at all.
	// A profile that sets it is walked with GETNEXT, one request per value.
	NoUseBulkWalkAll bool `yaml:"no_use_bulkwalkall"`

	Metrics    []MetricEntry `yaml:"metrics"`
	MetricTags []MetricTag   `yaml:"metric_tags"`
}

// MetricEntry is one element in the top-level metrics list.
// It represents either a scalar metric (Symbol) or a table metric (Table + Symbols).
type MetricEntry struct {
	MIB           string      `yaml:"MIB"`
	Symbol        *Symbol     `yaml:"symbol"`
	Table         *Table      `yaml:"table"`
	Symbols       []Symbol    `yaml:"symbols"`
	MetricTags    []MetricTag `yaml:"metric_tags"`
	WalkFullTable bool        `yaml:"walk_full_table,omitempty"`
}

// Symbol represents a single scalar SNMP OID to collect as a metric.
type Symbol struct {
	Name        string         `yaml:"name"`
	OID         string         `yaml:"OID"`
	Tag         string         `yaml:"tag"`
	PollTimeSec int            `yaml:"poll_time_sec"`
	Enum        map[string]int `yaml:"enum"`
	Conversion  string         `yaml:"conversion"`
	Format      string         `yaml:"format"`
	// Condition filters table rows: format "name=value". The name is either a
	// sibling symbol or a column the entry declares under metric_tags, and the
	// value is either a bare integer or a quoted string. Only rows whose
	// referenced column equals the value are emitted.
	Condition string `yaml:"condition"`
	// Script is a ktranslate transform of the polled value, written in its own
	// dialect. This collector runs none, so it is deserialized only to be able
	// to tell that the exported number would not be what the symbol names.
	Script string `yaml:"script"`
}

// Table identifies an SNMP table by name and root OID.
type Table struct {
	Name string `yaml:"name"`
	OID  string `yaml:"OID"`
}

// MetricTag defines a tag (dimension) derived from an OID column or scalar value.
type MetricTag struct {
	Tag    string     `yaml:"tag"`
	Column *TagColumn `yaml:"column"`
	Symbol *TagColumn `yaml:"symbol"` // alias used in some profiles
	MIB    string     `yaml:"MIB"`
	Table  string     `yaml:"table"`
	// Conversion is the rendering rule when a profile declares it beside the
	// tag rather than inside the column. It names the same column either way.
	// The column's own conversion is the more specific of the two and wins.
	Conversion string `yaml:"conversion"`
	// IndexTransform is set when Table names a table other than the one the
	// metric rows come from. It says which components of a metric row's
	// composite index identify the row in that other table.
	IndexTransform IndexTransform `yaml:"index_transform"`
}

// IndexRange selects a contiguous run of components from a composite table
// index. Start and End are zero-based positions in the dot-separated index and
// both ends are included.
type IndexRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

// IndexTransform maps a metric row's composite index onto the index of the
// table a MetricTag reads from. The selected runs are concatenated in the order
// they are declared.
type IndexTransform []IndexRange

// Apply returns the index into the referenced table for one metric row index.
//
// It reports false when a range is malformed or reaches past the row index, so
// a caller drops the join rather than looking up a wrong row.
func (t IndexTransform) Apply(rowIndex string) (string, bool) {
	if len(t) == 0 {
		return rowIndex, true
	}
	parts := strings.Split(rowIndex, ".")
	out := make([]string, 0, len(parts))
	for _, r := range t {
		if r.Start < 0 || r.End < r.Start || r.End >= len(parts) {
			return "", false
		}
		out = append(out, parts[r.Start:r.End+1]...)
	}
	return strings.Join(out, "."), true
}

// TagColumn is the OID source for a MetricTag value.
type TagColumn struct {
	OID        string         `yaml:"OID"`
	Name       string         `yaml:"name"`
	Enum       map[string]int `yaml:"enum"`
	Conversion string         `yaml:"conversion"`
	// MatchAttributes filters the rows of the entry the column belongs to. Each
	// element is a regular expression tested against the column's own rendered
	// value for a row, and a row matching any of them is kept.
	MatchAttributes []string `yaml:"match_attributes"`
}
