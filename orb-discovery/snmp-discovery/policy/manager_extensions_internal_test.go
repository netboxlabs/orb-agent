package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
)

// logLine is one slog JSON record, decoded far enough to assert on.
type logLine struct {
	Level               string `json:"level"`
	Msg                 string `json:"msg"`
	Directory           string `json:"directory"`
	File                string `json:"file"`
	Entries             int    `json:"entries"`
	Files               int    `json:"files"`
	ManufacturerEntries int    `json:"manufacturer_entries"`
	Err                 string `json:"error"`
}

func captureExtensionLogs(t *testing.T, dir string) []logLine {
	t.Helper()
	var buf bytes.Buffer
	m, err := NewManager(context.Background(),
		slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	lookup, err := data.LoadDeviceLookupExtensions(dir)
	if err != nil {
		t.Fatalf("LoadDeviceLookupExtensions: %v", err)
	}
	m.logReportedExtensionFiles(lookup, dir)

	var out []logLine
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var l logLine
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("decode log line %q: %v", raw, err)
		}
		out = append(out, l)
	}
	return out
}

func writeExtFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A file that parses to zero entries must be called out. Reporting plain
// success here is what left the operator in issue #486 with no way to tell that
// their custom OID had been ignored.
func TestLogReportedExtensionFiles_WarnsOnFileThatContributesNothing(t *testing.T) {
	dir := t.TempDir()
	// Valid YAML, but the top-level key is not "devices", so nothing registers.
	writeExtFile(t, dir, "fs_custom.yaml", "device:\n  .1.3.6.1.4.1.52642.1.439.0: S3400-24T4FP\n")

	var warned bool
	for _, l := range captureExtensionLogs(t, dir) {
		if l.Level == "WARN" && strings.Contains(l.Msg, "no device or manufacturer entries") {
			warned = true
			if l.File != "fs_custom.yaml" {
				t.Errorf("warning names file %q, want fs_custom.yaml", l.File)
			}
		}
	}
	if !warned {
		t.Error("a file contributing no entries must produce a WARN naming it")
	}
}

func TestLogReportedExtensionFiles_WarnsOnUnparseableFile(t *testing.T) {
	dir := t.TempDir()
	// A tab is not valid YAML indentation.
	writeExtFile(t, dir, "broken.yaml", "devices:\n\t.1.3.6.1.4.1.52642.1.439.0: S3400\n")

	var warned bool
	for _, l := range captureExtensionLogs(t, dir) {
		if l.Level == "WARN" && strings.Contains(l.Msg, "unparseable devices section") {
			warned = true
			if l.File != "broken.yaml" || l.Err == "" {
				t.Errorf("warning must name the file and the parse error, got file=%q err=%q", l.File, l.Err)
			}
		}
	}
	if !warned {
		t.Error("an unparseable file must produce a WARN carrying the parse error")
	}
}

// The success path has to report how much was actually loaded, which is the
// signal that was missing before.
func TestLogReportedExtensionFiles_ReportsEntryCount(t *testing.T) {
	dir := t.TempDir()
	writeExtFile(t, dir, "fs_custom.yaml",
		"devices:\n  .1.3.6.1.4.1.52642.1.439.0: S3400-24T4FP\n  .1.3.6.1.4.1.52642.1.440.0: S3400-48T4SP\n")

	lines := captureExtensionLogs(t, dir)
	var info *logLine
	for i := range lines {
		if lines[i].Level == "INFO" && lines[i].Msg == "loaded device lookup extensions" {
			info = &lines[i]
		}
	}
	if info == nil {
		t.Fatal("expected an INFO summary line")
	}
	if info.Entries != 2 {
		t.Errorf("entries = %d, want 2", info.Entries)
	}
	if info.Files != 1 {
		t.Errorf("files = %d, want 1", info.Files)
	}
}

// With no user directory there is nothing to count, and the message must stay
// as it was so existing log expectations are unaffected.
func TestLogReportedExtensionFiles_NoUserDirKeepsPlainMessage(t *testing.T) {
	lines := captureExtensionLogs(t, "")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1", len(lines))
	}
	if lines[0].Level != "INFO" || lines[0].Msg != "loaded device lookup extensions" {
		t.Errorf("got %s %q, want INFO loaded device lookup extensions", lines[0].Level, lines[0].Msg)
	}
	if lines[0].Entries != 0 || lines[0].Files != 0 {
		t.Errorf("counts must be absent for a built-in-only load, got entries=%d files=%d",
			lines[0].Entries, lines[0].Files)
	}
}

// A filename or parse error is operator-supplied and can echo file content, so
// it must not be able to forge extra log records. The logging this replaced
// stripped CR/LF deliberately; keep that guarantee here rather than resting on
// which slog handler happens to be installed.
func TestSanitizeLogValue(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain value untouched", "fs_custom.yaml", "fs_custom.yaml"},
		{"newline flattened", "a.yaml\nforged", "a.yaml forged"},
		{"carriage return flattened", "a.yaml\rforged", "a.yaml forged"},
		{"crlf becomes one space", "a.yaml\r\nforged", "a.yaml forged"},
		{"multi-line yaml error", "yaml: line 2:\n  bad indent", "yaml: line 2:   bad indent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLogValue(tc.in); got != tc.want {
				t.Errorf("sanitizeLogValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// End to end: a crafted filename must produce exactly one log record.
func TestLogReportedExtensionFiles_CraftedFilenameCannotForgeARecord(t *testing.T) {
	dir := t.TempDir()
	// A filename cannot contain a newline on most filesystems, so drive the
	// helper directly with a report whose file name carries one.
	var buf bytes.Buffer
	m, err := NewManager(context.Background(),
		slog.New(slog.NewJSONHandler(&buf, nil)), nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	writeExtFile(t, dir, "ok.yaml", "devices:\n  .1.3.6.1.4.1.9.1.1: m\n")
	lookup, err := data.LoadDeviceLookupExtensions(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.logReportedExtensionFiles(lookup, "/opt/orb\nFAKE level=ERROR msg=forged")

	records := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if records != 1 {
		t.Errorf("got %d log records, want 1; output:\n%s", records, buf.String())
	}
	if strings.Contains(buf.String(), "\nFAKE") {
		t.Error("a raw newline reached the log output")
	}
}

// The early-return branch logs the directory too, and it was the one call site
// that escaped sanitization: the existing crafted-value test only exercised the
// populated path, so it never touched this branch. Cover both.
func TestLogReportedExtensionFiles_CraftedDirIsSanitizedOnEveryPath(t *testing.T) {
	craftedDir := "/opt/orb\nFAKE level=ERROR msg=forged"

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string // returns the dir to load from
	}{
		{
			name: "early return, no user files",
			// No directory to build, so the helper is unused here.
			setup: func(_ *testing.T) string { return "" },
		},
		{
			name: "populated directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeExtFile(t, dir, "ok.yaml", "devices:\n  .1.3.6.1.4.1.9.1.1: m\n")
				return dir
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			m, err := NewManager(context.Background(),
				slog.New(slog.NewJSONHandler(&buf, nil)), nil, nil)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			lookup, err := data.LoadDeviceLookupExtensions(tc.setup(t))
			if err != nil {
				t.Fatal(err)
			}

			// Always report against the crafted directory string.
			m.logReportedExtensionFiles(lookup, craftedDir)

			// Assert on the decoded attribute, not the rendered line: slog
			// escapes newlines on output, so a raw value looks harmless there
			// while still being unsanitized in the record itself.
			out := strings.TrimSpace(buf.String())
			for _, raw := range strings.Split(out, "\n") {
				var l logLine
				if err := json.Unmarshal([]byte(raw), &l); err != nil {
					t.Fatalf("decode %q: %v", raw, err)
				}
				if strings.ContainsAny(l.Directory, "\r\n") {
					t.Errorf("directory attribute still carries a newline: %q", l.Directory)
				}
			}
		})
	}
}

// A file carrying only a manufacturers: block declares no devices by design.
// The manufacturer resolver reads the same directory and applies its overrides,
// so warning about it would nag a healthy configuration.
func TestLogReportedExtensionFiles_NoWarnForManufacturerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	writeExtFile(t, dir, "mfr.yaml", "manufacturers:\n  52642: FS\n")

	for _, l := range captureExtensionLogs(t, dir) {
		if l.Level == "WARN" {
			t.Errorf("manufacturer-only file must not warn, got: %s %q file=%q", l.Level, l.Msg, l.File)
		}
	}
}

// The counterpart: a file with neither recognised section still warns.
func TestLogReportedExtensionFiles_WarnsWhenNeitherSectionContributes(t *testing.T) {
	dir := t.TempDir()
	writeExtFile(t, dir, "typo.yaml", "device:\n  .1.3.6.1.4.1.52642.1.439.0: S3400\n")

	var warned bool
	for _, l := range captureExtensionLogs(t, dir) {
		if l.Level == "WARN" && strings.Contains(l.Msg, "no device or manufacturer entries") {
			warned = true
		}
	}
	if !warned {
		t.Error("a file contributing neither devices nor manufacturers must warn")
	}
}

// A configured directory holding no .yaml/.yml files means none of the
// operator's files were considered. Logging the plain success message there
// recreates exactly the misleading success this reporting exists to remove: the
// previous loader at least logged a line per skipped file.
func TestLogReportedExtensionFiles_WarnsWhenDirHasNoYamlFiles(t *testing.T) {
	dir := t.TempDir()
	writeExtFile(t, dir, "custom.yaml.bak", "devices:\n  .1.2.3: m\n")

	var warned bool
	for _, l := range captureExtensionLogs(t, dir) {
		if l.Level == "WARN" && strings.Contains(l.Msg, "no .yaml") {
			warned = true
		}
	}
	if !warned {
		t.Error("a directory with no usable YAML files must warn, not report success")
	}
}

// A devices: section that fails to parse does not stop the manufacturers:
// section of the same file being applied, so the warning must not imply the
// whole file was discarded.
func TestLogReportedExtensionFiles_ParseFailureScopedToDeviceSection(t *testing.T) {
	dir := t.TempDir()
	writeExtFile(t, dir, "mixed.yaml",
		"devices:\n  .1.3.6.1.4.1.1: {nested: map}\nmanufacturers:\n  52642: FS\n")

	var found *logLine
	lines := captureExtensionLogs(t, dir)
	for i := range lines {
		if lines[i].Level == "WARN" {
			found = &lines[i]
		}
	}
	if found == nil {
		t.Fatal("a devices-section parse failure must still warn")
	}
	if strings.Contains(found.Msg, "skipping it") {
		t.Errorf("warning implies the whole file was skipped: %q", found.Msg)
	}
	if !strings.Contains(found.Msg, "device") {
		t.Errorf("warning should identify the device entries as the skipped part: %q", found.Msg)
	}
	if found.ManufacturerEntries != 1 {
		t.Errorf("manufacturer_entries = %d, want 1 so the operator sees that part still applied",
			found.ManufacturerEntries)
	}
}
