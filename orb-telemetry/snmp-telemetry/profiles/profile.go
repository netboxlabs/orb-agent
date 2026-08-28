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

// Profile is the top-level representation of a ktranslate-compatible SNMP profile file.
type Profile struct {
	// FileName is the base filename, populated by the Loader (not from YAML).
	FileName string `yaml:"-"`

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
