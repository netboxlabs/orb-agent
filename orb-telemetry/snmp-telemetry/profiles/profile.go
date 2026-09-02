package profiles

import (
	"fmt"
	"maps"
	"slices"
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

// Match is one entry of the ordered `matches_list` form of a sysDescr
// redirect: the pattern to test a device's sysDescr against, and the basename
// of the profile a device it describes is collected with instead.
type Match struct {
	Regex  string `yaml:"regex"`
	Target string `yaml:"target"`
}

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
	// MatchesList is the ordered spelling of the same sysDescr redirect
	// Matches carries. It is not an alias: a map has no order, so a profile
	// whose sysDescr satisfies two of its patterns has no stable answer under
	// Matches alone, and this form is what a profile in that position is meant
	// to use. Its entries are evaluated in the order written, and all of them
	// before any Matches entry.
	MatchesList []Match `yaml:"matches_list"`
	// NoUseBulkWalkAll marks an agent that answers GETBULK badly or not at all.
	// A profile that sets it is walked with GETNEXT, one request per value.
	NoUseBulkWalkAll bool `yaml:"no_use_bulkwalkall"`

	Metrics    []MetricEntry `yaml:"metrics"`
	MetricTags []MetricTag   `yaml:"metric_tags"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Profile.
//
// It exists for the capitalised `sysObjectID` spelling. Key matching is
// case-sensitive, so a profile writing that spelling declared no match key at
// all and was indexed under nothing: it matched no device however many OIDs it
// listed. The two spellings name the same field, so the alias fills
// SysObjectID when the documented spelling left it empty.
func (p *Profile) UnmarshalYAML(value *yaml.Node) error {
	// A distinct type with none of Profile's methods, so decoding into it does
	// not re-enter this one.
	type plain Profile
	if err := value.Decode((*plain)(p)); err != nil {
		return err
	}
	if len(p.SysObjectID) > 0 {
		return nil
	}
	var alias struct {
		SysObjectID StringOrSlice `yaml:"sysObjectID"`
	}
	if err := value.Decode(&alias); err != nil {
		return err
	}
	p.SysObjectID = alias.SysObjectID
	return nil
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

	// FromExtended is true when the entry reached a resolved profile through
	// `extends:` instead of being written in that profile's own file.
	// Populated by the Loader. It decides a metric name collision: an entry a
	// profile declares itself outranks one it inherited.
	FromExtended bool `yaml:"-"`

	// Name, OID and Type are the flat form: instead of nesting the metric
	// under `symbol:`, the entry carries the OID to read, the name to write it
	// to and the kind of thing the OID names. A `help:` sits beside them and
	// has no home here, since instrument descriptions are synthesized from the
	// metric name.
	//
	// They are kept after UnmarshalYAML folded the readable ones into Symbol,
	// so the loader can name the entries it could not fold.
	Name string `yaml:"name"`
	OID  string `yaml:"oid"`
	Type string `yaml:"type"`
}

// UnmarshalYAML implements yaml.Unmarshaler for MetricEntry.
//
// The flat form describes exactly what a `symbol:` does, one OID to read under
// one metric name, so a flat entry naming a readable type is read as the
// symbol it describes. The nested forms are the documented ones and win, and
// the types this collector cannot read are left for the loader to report:
// flatEntryReason says which and why.
func (m *MetricEntry) UnmarshalYAML(value *yaml.Node) error {
	type plain MetricEntry
	if err := value.Decode((*plain)(m)); err != nil {
		return err
	}
	if !m.usesFlatForm() || flatEntryReason(m) != "" {
		return nil
	}
	m.Symbol = &Symbol{Name: m.Name, OID: m.OID}
	return nil
}

// usesFlatForm reports whether the entry describes its metric on the entry
// itself rather than under `symbol:`, `symbols:` or `table:`. A promoted entry
// carries a symbol, so it stops using the flat form once it is read.
func (m *MetricEntry) usesFlatForm() bool {
	return m.OID != "" && m.Symbol == nil && m.Table == nil && len(m.Symbols) == 0
}

// flatEntryReason says why a flat metric entry was not read as a symbol, or ""
// when it was read or when the entry does not use the flat form at all.
//
// Only a value the collector can walk and export becomes a symbol. A trap OID
// names a notification, which has no instance to read. A table entry names an
// entry OID and no columns, and a table is collected column by column, so
// there is nothing to ask the device for. An entry with no name has no metric
// to write to.
func flatEntryReason(m *MetricEntry) string {
	if !m.usesFlatForm() {
		return ""
	}
	switch m.Type {
	case "gauge", "counter":
	case "":
		return "the entry declares no type"
	default:
		return "the collector reads no value from a " + m.Type + " entry"
	}
	if m.Name == "" {
		return "the entry names no metric"
	}
	return ""
}

// Enum maps an enum member's name to the integer a device reports for it, and
// keeps the names a profile declared without one.
//
// A member written with no value decodes to integer 0 under a plain map, which
// invents a mapping the profile never wrote: a device reporting 0 is labelled
// with that member's name, and where the profile also gives a real member the
// value 0 the two collide and which name a lookup returns varies with map
// order. Such a member is left out of Values and named in Unset instead, so it
// labels nothing and can be reported.
type Enum struct {
	// Values are the members carrying a value, keyed by member name.
	Values map[string]int
	// Unset names the members declared without one, in the order written.
	Unset []string
}

// Name returns the member val falls on, or "" when no member carries it or
// more than one does.
//
// A profile can give one value to two members, and there is no ground for
// preferring either name: the device reported a number, and the profile says
// it means both things. Ranging the map answered with whichever came first
// that time, so one device's unchanged reading alternated its label between
// polls and split into two series. Naming a fixed winner would settle the
// series and still be the wrong name about half the time, so such a value is
// left unlabelled and reported instead.
func (e Enum) Name(val int64) string {
	var name string
	found := 0
	for n, v := range e.Values {
		if int64(v) == val {
			name = n
			found++
		}
	}
	if found != 1 {
		return ""
	}
	return name
}

// EnumCollision is one value that more than one enum member carries, with the
// members that carry it.
type EnumCollision struct {
	Value int
	Names []string
}

// Duplicated returns the values more than one member carries, by ascending
// value, each with its member names in order. It is empty for the enums that
// map every value once, which is nearly all of them.
func (e Enum) Duplicated() []EnumCollision {
	byValue := make(map[int][]string, len(e.Values))
	for name, v := range e.Values {
		byValue[v] = append(byValue[v], name)
	}
	var out []EnumCollision
	for _, v := range slices.Sorted(maps.Keys(byValue)) {
		if len(byValue[v]) < 2 {
			continue
		}
		out = append(out, EnumCollision{Value: v, Names: slices.Sorted(slices.Values(byValue[v]))})
	}
	return out
}

// Len returns the number of members that map a value.
func (e Enum) Len() int { return len(e.Values) }

// UnmarshalYAML implements yaml.Unmarshaler for Enum.
//
// A member whose value is absent is recorded in Unset rather than mapped. A
// value that is present but not an integer is still an error, so a profile
// carrying one keeps being skipped whole rather than losing one member.
func (e *Enum) UnmarshalYAML(value *yaml.Node) error {
	if value.ShortTag() == "!!null" {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("unsupported YAML node kind %v for Enum", value.Kind)
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		var name string
		if err := value.Content[i].Decode(&name); err != nil {
			return err
		}
		if value.Content[i+1].ShortTag() == "!!null" {
			e.Unset = append(e.Unset, name)
			continue
		}
		var v int
		if err := value.Content[i+1].Decode(&v); err != nil {
			return err
		}
		if e.Values == nil {
			e.Values = make(map[string]int, len(value.Content)/2)
		}
		e.Values[name] = v
	}
	return nil
}

// Symbol represents a single scalar SNMP OID to collect as a metric.
type Symbol struct {
	Name        string `yaml:"name"`
	OID         string `yaml:"OID"`
	Tag         string `yaml:"tag"`
	PollTimeSec int    `yaml:"poll_time_sec"`
	Enum        Enum   `yaml:"enum"`
	Conversion  string `yaml:"conversion"`
	Format      string `yaml:"format"`
	// Condition filters table rows: format "name=value". The name is either a
	// sibling symbol or a column the entry declares under metric_tags, and the
	// value is either a bare integer or a quoted string. Only rows whose
	// referenced column equals the value are emitted.
	Condition string `yaml:"condition"`
	Script    string `yaml:"script"`
	// AllowDup keeps the symbol exporting when another symbol resolves to the
	// same metric name. Without it the loser of that contest is dropped.
	AllowDup bool `yaml:"allow_duplicate"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Symbol.
//
// It exists for the `convert` spelling. One bundled profile writes it where
// every other declaration in the tree writes `conversion`, and key matching is
// case-sensitive and exact, so those symbols declared no conversion at all:
// their OctetString readings reached the value conversion with nothing to apply
// and were dropped as non-numeric. The two spellings name the same field, so
// the alias fills Conversion when the documented spelling left it empty. They
// are peers rather than a general and a specific declaration, so the documented
// spelling wins, as it does for the `sysObjectID` alias.
func (s *Symbol) UnmarshalYAML(value *yaml.Node) error {
	// A distinct type with none of Symbol's methods, so decoding into it does
	// not re-enter this one.
	type plain Symbol
	if err := value.Decode((*plain)(s)); err != nil {
		return err
	}
	if s.Conversion != "" {
		return nil
	}
	var alias struct {
		Conversion string `yaml:"convert"`
	}
	if err := value.Decode(&alias); err != nil {
		return err
	}
	s.Conversion = alias.Conversion
	return nil
}

// ExportName returns the name the symbol's metric is written under: its `tag:`
// when it declares one, and its `name:` otherwise.
//
// A tag renames the metric rather than dimensioning it. Upstream reads the
// field the same way, and a profile giving two symbols one tag is declaring
// that both report the same thing under one name.
func (s *Symbol) ExportName() string {
	if s.Tag != "" {
		return s.Tag
	}
	return s.Name
}

// metricNamePrefix namespaces every metric the collector exports from a profile.
const metricNamePrefix = "snmp."

// MetricName returns the OTLP metric name the symbol's points are exported
// under: its export name, lowercased, under the collector's prefix.
//
// This is the one place the exported name is decided. The collector writes
// under it and the duplicate contest is held on it, so a profile declaring
// `CPU` beside `cpu` is two symbols claiming one series and the contest sees
// that. Two rules would drift, and one of them would let those two symbols
// observe the series twice.
func (s *Symbol) MetricName() string {
	return metricNamePrefix + strings.ToLower(s.ExportName())
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
	// Index is a bare selector a profile occasionally writes beside a column.
	// It is deserialized to be reported rather than applied: upstream parses
	// the field and acts on it nowhere, and the one bundled use declares it on
	// a column whose table shares the metric table's index, where reading it as
	// a component selector would key the join by fewer components than the
	// column's rows carry and drop a tag that lands today.
	Index int `yaml:"index"`
	// OID and Name are the direct form: a profile leaves `column:` empty and
	// writes the column's OID and name on the tag itself. They describe the
	// same column the nested form does, so a tag declaring them is read as one
	// that declared a column.
	OID  string `yaml:"OID"`
	Name string `yaml:"name"`
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
	OID  string `yaml:"OID"`
	Name string `yaml:"name"`
	// Tag is the attribute key when a profile writes it inside the column
	// rather than beside it. It names the same key either way. The column's
	// own tag is the more specific of the two and wins.
	Tag        string `yaml:"tag"`
	Enum       Enum   `yaml:"enum"`
	Conversion string `yaml:"conversion"`
	// MatchAttributes filters the rows of the entry the column belongs to. Each
	// element is a regular expression tested against the column's own rendered
	// value for a row, and a row matching any of them is kept.
	MatchAttributes []string `yaml:"match_attributes"`
}
