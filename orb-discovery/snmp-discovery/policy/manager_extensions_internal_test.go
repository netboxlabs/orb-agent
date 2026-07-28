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
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	File    string `json:"file"`
	Entries int    `json:"entries"`
	Files   int    `json:"files"`
	Err     string `json:"error"`
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
		if l.Level == "WARN" && strings.Contains(l.Msg, "no device entries") {
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
		if l.Level == "WARN" && strings.Contains(l.Msg, "could not be parsed") {
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
