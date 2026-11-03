package gnmi

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetupTimeout bounds each call a connection makes before it delivers: the
// Capabilities call and the subscription-path probe.
const SetupTimeout = 10 * time.Second

// Transient reports whether err is a call that got no answer about the request:
// the target was unreachable, busy, slow or not accepting the login yet. A retry
// can succeed, so such an error is never kept as the target's verdict.
func Transient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Aborted:
		return true
	default:
		return false
	}
}
