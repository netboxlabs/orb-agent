package data

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed manufacturers.yaml
var manufacturersData embed.FS

// ManufacturerRetriever is an interface that provides a method to retrieve a manufacturer by ID
type ManufacturerRetriever interface {
	GetManufacturer(id string) (string, error)
}

// ManufacturerLookup represents a manufacturer lookup service
type ManufacturerLookup struct {
	data *map[string]string
}

// NewManufacturerLookup creates a new manufacturer lookup service
func NewManufacturerLookup() (*ManufacturerLookup, error) {
	file, err := manufacturersData.Open("manufacturers.yaml")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("Error closing file:", err)
		}
	}()

	manufacturers := make(map[string]string)
	// Don't use yaml.Unmarshal because it is way too slow for a large file
	scanner := bufio.NewScanner(file)

	// Skip the first line which is "manufacturers:"
	_ = scanner.Scan()

	// Parse each line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse lines in format "  ID: Name"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		id := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		manufacturers[id] = name
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &ManufacturerLookup{
		data: &manufacturers,
	}, nil
}

// GetManufacturer returns the manufacturer name for a given ID
func (m *ManufacturerLookup) GetManufacturer(id string) (string, error) {
	if name, ok := (*m.data)[id]; ok {
		return name, nil
	}
	return "", fmt.Errorf("manufacturer not found")
}

// ManufacturerResolver wraps a built-in ManufacturerLookup with user-supplied
// overrides loaded from lookup_extensions YAML files. Overrides are keyed by
// IANA PEN (integer encoded as a string) and consulted first; if no override
// matches, the lookup falls back to the built-in catalog.
type ManufacturerResolver struct {
	builtin   ManufacturerRetriever
	overrides map[string]string
}

// NewManufacturerResolver builds a resolver from the given built-in lookup,
// merging the optional manufacturers: blocks from (a) the embedded
// snmp-discovery lookup_extensions/*.yaml and (b) every *.yaml/*.yml file
// under userDir (if non-empty). User overrides take precedence over
// built-in extension overrides, which take precedence over the IANA catalog.
//
// The built-in extension scan is parsed once per process and cached, so
// callers (including per-policy StartPolicy invocations) only pay the
// userDir merge cost on subsequent constructions.
//
// logger receives non-fatal warnings emitted while loading user override
// files (missing directory, unreadable file, malformed YAML). A nil logger
// is permitted; warnings are silently dropped in that case.
func NewManufacturerResolver(builtin ManufacturerRetriever, userDir string, logger *slog.Logger) (*ManufacturerResolver, error) {
	cached, err := getBuiltInManufacturerOverrides()
	if err != nil {
		return nil, err
	}
	overrides := make(map[string]string, len(cached))
	for k, v := range cached {
		overrides[k] = v
	}

	if userDir != "" {
		if err := loadUserManufacturerOverrides(userDir, overrides, logger); err != nil {
			return nil, err
		}
	}

	return &ManufacturerResolver{
		builtin:   builtin,
		overrides: overrides,
	}, nil
}

// getBuiltInManufacturerOverrides parses the embedded lookup_extensions/*.yaml
// manufacturers blocks once per process and returns the cached map. The
// returned map is not safe to mutate — callers must clone before merging
// user overrides.
var (
	builtInManufacturerOverridesOnce sync.Once
	builtInManufacturerOverrides     map[string]string
	builtInManufacturerOverridesErr  error
)

func getBuiltInManufacturerOverrides() (map[string]string, error) {
	builtInManufacturerOverridesOnce.Do(func() {
		overrides := make(map[string]string)
		if err := loadBuiltInManufacturerOverrides(overrides); err != nil {
			builtInManufacturerOverridesErr = err
			return
		}
		builtInManufacturerOverrides = overrides
	})
	return builtInManufacturerOverrides, builtInManufacturerOverridesErr
}

// GetManufacturer returns the manufacturer name for an IANA PEN, honoring
// user/extension overrides before falling back to the built-in catalog.
func (r *ManufacturerResolver) GetManufacturer(id string) (string, error) {
	if name, ok := r.overrides[id]; ok {
		return name, nil
	}
	return r.builtin.GetManufacturer(id)
}

func loadBuiltInManufacturerOverrides(overrides map[string]string) error {
	files, err := lookupExtensionsData.ReadDir("lookup_extensions")
	if err != nil {
		return fmt.Errorf("failed to read directory lookup_extensions: %w", err)
	}
	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}
		filePath := path.Join("lookup_extensions", file.Name())
		extensionFile, err := lookupExtensionsData.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", file.Name(), err)
		}
		fileData, err := io.ReadAll(extensionFile)
		if cerr := extensionFile.Close(); cerr != nil {
			log.Printf("Error closing file %s: %v", filePath, cerr)
		}
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file.Name(), err)
		}
		if err := loadManufacturerYAML(fileData, overrides); err != nil {
			return fmt.Errorf("failed to load manufacturers from %s: %w", file.Name(), err)
		}
	}
	return nil
}

func loadUserManufacturerOverrides(dir string, overrides map[string]string, logger *slog.Logger) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		warn(logger, "failed to read manufacturer overrides directory", "directory", dir, "error", err)
		return nil
	}
	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}
		filePath := filepath.Join(dir, file.Name())
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			// Soft-fail per file: a single unreadable file must not
			// drop every other override (including built-in extension
			// blocks already merged into overrides above).
			warn(logger, "failed to read manufacturer overrides file", "file", filePath, "error", err)
			continue
		}
		if err := loadManufacturerYAML(fileData, overrides); err != nil {
			warn(logger, "failed to load manufacturer overrides", "file", filePath, "error", err)
			continue
		}
	}
	return nil
}

// warn forwards a structured warning to logger, or silently drops it when
// logger is nil. Centralizes the nil-check so call sites stay terse.
func warn(logger *slog.Logger, msg string, args ...any) {
	if logger == nil {
		return
	}
	logger.Warn(msg, args...)
}

// loadManufacturerYAML parses the optional manufacturers: block from a
// lookup-extension YAML file and merges it into overrides. Files without
// the block are silently ignored (they only carry devices:).
func loadManufacturerYAML(fileData []byte, overrides map[string]string) error {
	var parsed struct {
		Manufacturers map[string]string `yaml:"manufacturers"`
	}
	if err := yaml.Unmarshal(fileData, &parsed); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}
	for id, name := range parsed.Manufacturers {
		overrides[id] = name
	}
	return nil
}

// devRefKind discriminates a devices[] map value between a literal model
// string and an already-walked OID reference whose value becomes the model.
type devRefKind uint8

const (
	devRefStatic devRefKind = iota
	devRefDynamic
)

// deviceRef is the stored form of a lookup_extensions devices[] entry after
// the loader classifies the raw YAML value.
type deviceRef struct {
	kind      devRefKind
	literal   string // populated when kind == devRefStatic
	sourceOID string // populated when kind == devRefDynamic; format: ".1.3.6..." or "1.3.6..."
}

// oidPattern matches an SNMP numeric OID (optionally leading dot).
// Any map value that matches is treated as a dynamic reference.
var oidPattern = regexp.MustCompile(`^\.?\d+(\.\d+)+$`)

func classifyDeviceValue(value string) deviceRef {
	if oidPattern.MatchString(value) {
		return deviceRef{kind: devRefDynamic, sourceOID: value}
	}
	return deviceRef{kind: devRefStatic, literal: value}
}

// DeviceRetriever is an interface that provides methods to retrieve device
// information by device OID. GetDevice returns the model name for static
// entries only and is preserved for backward compatibility. GetDeviceModel
// additionally resolves dynamic references (where the YAML value is an
// OID whose walked value is the model name).
type DeviceRetriever interface {
	GetDevice(deviceOID string) (string, error)
	GetDeviceModel(deviceOID string, walked map[string]string) (string, error)
}

// DeviceLookup represents a device lookup service.
type DeviceLookup struct {
	devicesByVendor   map[string]deviceRef
	userExtensionFile []ExtensionFileResult
}

// ExtensionFileResult records what one file in lookup_extensions_dir
// contributed.
//
// A file can be read successfully and still contribute nothing: a wrong
// top-level key or bad indentation yields an empty devices map with no error.
// Reporting Entries alongside Err lets the caller distinguish "loaded 12
// entries" from "loaded, but your OID was never registered", which is otherwise
// indistinguishable from the logs (issue #486).
type ExtensionFileResult struct {
	// Name is the file's base name, not its path.
	Name string
	// Entries is how many device OIDs the file registered.
	Entries int
	// ManufacturerEntries is how many manufacturer overrides the file declares.
	// A file may legitimately carry only a manufacturers: block: the same
	// directory is also read by NewManufacturerResolver, which applies those
	// overrides. Callers must not treat such a file as contributing nothing.
	ManufacturerEntries int
	// Err is set when the file could not be parsed. Such a file is skipped
	// rather than failing the whole load, so the rest still apply.
	Err error
}

// UserExtensionFiles reports what each YAML file in lookup_extensions_dir
// contributed, in directory order. Empty when no user directory was configured.
func (d *DeviceLookup) UserExtensionFiles() []ExtensionFileResult {
	return d.userExtensionFile
}

// lookupOIDBothSpellings indexes m by oid, accepting either leading-dot or
// no-leading-dot spellings since callers and YAML authors may disagree.
func lookupOIDBothSpellings[V any](m map[string]V, oid string) (V, bool) {
	if v, ok := m[oid]; ok {
		return v, true
	}
	alt := strings.TrimPrefix(oid, ".")
	if v, ok := m[alt]; ok {
		return v, true
	}
	if v, ok := m["."+alt]; ok {
		return v, true
	}
	var zero V
	return zero, false
}

// GetDevice returns the device name for a given device OID using only the
// static catalog. Dynamic references cannot be resolved without a walked
// OID map; callers that need them must use GetDeviceModel.
func (d *DeviceLookup) GetDevice(deviceOID string) (string, error) {
	ref, ok := lookupOIDBothSpellings(d.devicesByVendor, deviceOID)
	if !ok {
		return "", fmt.Errorf("device ID %s not found", deviceOID)
	}
	if ref.kind == devRefStatic {
		return ref.literal, nil
	}
	return "", fmt.Errorf("device ID %s resolves dynamically; call GetDeviceModel", deviceOID)
}

// GetDeviceModel resolves a device model name. For static entries it returns
// the literal; for dynamic entries it reads walked[sourceOID], trims null
// bytes and whitespace, and returns the result (or an error if the source
// OID is missing or empty).
//
// Callers pass the walked OID->string map for the current scan so that
// dynamic references (e.g. a shared sysObjectID that indexes into
// sysDescr) can resolve without performing extra SNMP traffic.
func (d *DeviceLookup) GetDeviceModel(deviceOID string, walked map[string]string) (string, error) {
	ref, ok := lookupOIDBothSpellings(d.devicesByVendor, deviceOID)
	if !ok {
		return "", fmt.Errorf("device ID %s not found", deviceOID)
	}
	if ref.kind == devRefStatic {
		return ref.literal, nil
	}
	value, ok := lookupOIDBothSpellings(walked, ref.sourceOID)
	if !ok {
		return "", fmt.Errorf("device ID %s references walked OID %s which was not found in the walk set", deviceOID, ref.sourceOID)
	}
	trimmed := strings.TrimRight(value, "\x00 \t\n\r")
	trimmed = strings.TrimLeft(trimmed, "\x00 \t\n\r")
	if trimmed == "" {
		return "", fmt.Errorf("device ID %s references walked OID %s whose value is empty", deviceOID, ref.sourceOID)
	}
	return trimmed, nil
}

//go:embed lookup_extensions/*.yaml
var lookupExtensionsData embed.FS

// LoadDeviceLookupExtensions loads device data from YAML files in the specified directory
func LoadDeviceLookupExtensions(dir string) (*DeviceLookup, error) {
	devicesByVendor := make(map[string]deviceRef)
	deviceLookup := DeviceLookup{
		devicesByVendor: devicesByVendor,
	}

	err := loadBuiltInExtensions(devicesByVendor)
	if err != nil {
		return &deviceLookup, err
	}

	if dir != "" {
		// Extend built in extensions with user provided extensions
		results, err := loadUserProvidedExtensions(dir, devicesByVendor)
		if err != nil {
			return &deviceLookup, err
		}
		deviceLookup.userExtensionFile = results
	}

	return &deviceLookup, nil
}

func loadBuiltInExtensions(devicesByVendor map[string]deviceRef) error {
	files, err := lookupExtensionsData.ReadDir("lookup_extensions")
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", "lookup_extensions", err)
	}

	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}

		filePath := path.Join("lookup_extensions", file.Name())
		extensionFile, err := lookupExtensionsData.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", file.Name(), err)
		}

		extensionFileData, err := io.ReadAll(extensionFile)
		if cerr := extensionFile.Close(); cerr != nil {
			log.Printf("Error closing file %s: %v", filePath, cerr)
		}
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file.Name(), err)
		}

		if err := loadYAMLFile(extensionFileData, devicesByVendor); err != nil {
			return fmt.Errorf("failed to load YAML file %s: %w", file.Name(), err)
		}
	}
	return nil
}

// countManufacturerEntries reports how many manufacturer overrides a
// lookup-extension file declares, for reporting only. The overrides themselves
// are applied by NewManufacturerResolver, which reads the same directory.
//
// Keys are IANA Private Enterprise Numbers and so are numeric in YAML; decoding
// into map[string]any lets them be counted without caring about their type.
func countManufacturerEntries(data []byte) int {
	var probe struct {
		Manufacturers map[string]any `yaml:"manufacturers"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return 0
	}
	return len(probe.Manufacturers)
}

// loadUserProvidedExtensions merges every YAML file in dir into
// devicesByVendor and returns one result per file for the caller to log.
//
// A file that fails to parse is skipped rather than aborting the load, so one
// bad file cannot cost an operator every other override they wrote. The failure
// is returned in the results instead of being logged here, so it reaches the
// structured logger the caller already holds.
func loadUserProvidedExtensions(dir string, devicesByVendor map[string]deviceRef) ([]ExtensionFileResult, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var results []ExtensionFileResult
	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}

		filePath := filepath.Join(dir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
		}

		// Parse into a per-file map first so the entry count is this file's own
		// contribution rather than the running total, then merge. Merging only
		// on success keeps the pre-existing behaviour that a rejected file
		// contributes nothing.
		fileRefs := make(map[string]deviceRef)
		parseErr := loadYAMLFile(data, fileRefs)
		if parseErr == nil {
			for oid, ref := range fileRefs {
				devicesByVendor[oid] = ref
			}
		}
		results = append(results, ExtensionFileResult{
			Name:                file.Name(),
			Entries:             len(fileRefs),
			ManufacturerEntries: countManufacturerEntries(data),
			Err:                 parseErr,
		})
	}
	return results, nil
}

func isLookupExtensionFile(file os.DirEntry) bool {
	return !file.IsDir() &&
		(strings.HasSuffix(strings.ToLower(file.Name()), ".yaml") ||
			strings.HasSuffix(strings.ToLower(file.Name()), ".yml"))
}

// loadYAMLFile loads a single YAML file and merges its data into
// devicesByVendor, classifying each value as a static literal or a
// dynamic OID reference.
func loadYAMLFile(data []byte, devicesByVendor map[string]deviceRef) error {
	var fileData struct {
		Devices map[string]string `yaml:"devices"`
	}

	if err := yaml.Unmarshal(data, &fileData); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	for deviceOID, deviceValue := range fileData.Devices {
		devicesByVendor[deviceOID] = classifyDeviceValue(deviceValue)
	}

	return nil
}

// defaultOIDPattern matches OIDs rooted at the standard SNMP Internet
// sub-tree (.1.3.6.1.*). This is intentionally stricter than oidPattern:
// PolicyConfig defaults like defaults.location may already contain
// dotted-decimal literals (e.g. "3.14.159" as a room number, or
// "10.0.0.1"), and silently re-classifying them as OID references would
// be a backward-compat break.
var defaultOIDPattern = regexp.MustCompile(`^\.1\.3\.6\.1\.(\d+\.)+\d+$`)

// ResolveDefault classifies raw as either a literal value or an SNMP OID
// reference and resolves it against the walked map.
//
// If raw matches defaultOIDPattern, it is treated as an OID reference:
// the function returns the corresponding value from walked, with NULL
// bytes and surrounding whitespace trimmed from both ends. Both
// leading-dot and no-leading-dot spellings are tolerated on the lookup
// side.
//
// If raw is not an OID, it is treated as a literal and returned after
// trimming surrounding whitespace.
//
// ok is false when:
//   - raw is empty or whitespace-only,
//   - raw is an OID reference and the OID is missing from walked,
//   - raw is an OID reference and the resolved value is empty after
//     trimming.
//
// The regex requires the .1.3.6.1.* root so legitimate non-SNMP
// dotted-decimal literals (room numbers, IPs) cannot collide with the
// OID-reference syntax. This is stricter than the lookup_extensions
// oidPattern used by GetDeviceModel.
func ResolveDefault(raw string, walked map[string]string) (string, bool) {
	if defaultOIDPattern.MatchString(raw) {
		if walked == nil {
			return "", false
		}
		value, ok := lookupOIDBothSpellings(walked, raw)
		if !ok {
			return "", false
		}
		trimmed := strings.Trim(value, "\x00 \t\n\r")
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}
