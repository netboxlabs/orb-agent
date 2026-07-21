package filesmgr

import "context"

var _ Manager = (*dummyFilesManager)(nil)

// dummyFilesManager is the no-op Manager returned when files delivery is not
// active. Get always reports "not installed" so consumers (e.g. the worker
// backend) fall back to their baked binaries; every other operation no-ops.
type dummyFilesManager struct{}

func (dummyFilesManager) Start(context.Context) error                      { return nil }
func (dummyFilesManager) Stop(context.Context) error                       { return nil }
func (dummyFilesManager) Ensure(context.Context, FileSpec) (string, error) { return "", nil }
func (dummyFilesManager) Get(string) (FileEntry, bool)                     { return FileEntry{}, false }
func (dummyFilesManager) List() []FileEntry                                { return nil }
func (dummyFilesManager) ListFailures() []FailureEntry                     { return nil }
func (dummyFilesManager) Remove(context.Context, string) error             { return nil }
func (dummyFilesManager) Rollback(context.Context, string) error           { return nil }
func (dummyFilesManager) Subscribe(func(FileEvent)) func()                 { return func() {} }
