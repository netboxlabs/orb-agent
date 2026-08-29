package profiles

import (
	"fmt"

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
	// Condition filters table rows: format "OtherSymbolName=<intValue>".
	// Only rows where the referenced symbol equals the given value are emitted.
	Condition string `yaml:"condition"`
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
}

// TagColumn is the OID source for a MetricTag value.
type TagColumn struct {
	OID        string         `yaml:"OID"`
	Name       string         `yaml:"name"`
	Enum       map[string]int `yaml:"enum"`
	Conversion string         `yaml:"conversion"`
}
