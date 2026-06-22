package mapping

import (
	"log/slog"
	"os"
	"reflect"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// fakePostMapper is a no-op postPassMapper used to assert PostMap order.
type fakePostMapper struct {
	name string
	log  *[]string
}

func (f *fakePostMapper) Map(map[ObjectIDIndex]*ObjectIDValue, *Entry, *EntityRegistry, *config.Defaults) diode.Entity {
	return nil
}

func (f *fakePostMapper) PostMap(ObjectIDValueMap, *EntityRegistry, *config.Defaults) []diode.Entity {
	*f.log = append(*f.log, f.name)
	return nil
}

func TestPostMap_RegistrationOrder(t *testing.T) {
	log := []string{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := &Config{
		mapping:            map[string]*Entry{},
		inetAddressEntries: map[string]*Entry{},
	}
	mapper := &ObjectIDMapper{
		mappingConfig: cfg,
		logger:        logger,
		registry:      NewEntityRegistry(logger),
		defaults:      &config.Defaults{},
		postPassMappers: []postPassMapper{
			&fakePostMapper{name: "first", log: &log},
			&fakePostMapper{name: "second", log: &log},
			&fakePostMapper{name: "third", log: &log},
		},
	}
	_ = mapper.MapObjectIDsToEntity(ObjectIDValueMap{})
	want := []string{"first", "second", "third"}
	if !reflect.DeepEqual(log, want) {
		t.Fatalf("PostMap order: got %v, want %v", log, want)
	}
}
