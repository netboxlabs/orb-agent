package backend

import "errors"

// notSentError marks an error ApplyPolicy returned before it sent the
// backend's process anything.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }

func (e *notSentError) Unwrap() error { return e.err }

// NotSent marks err, an error ApplyPolicy returns, as one returned before
// the backend sent its process anything, such as a policy the backend
// refuses to send: the process holds nothing more of the policy, a tap or
// other state created for it included, than it did before the call. The
// policy manager then keeps what it knew before the call, so a policy that
// never reached the backend is still applied fresh next time, and removed
// without asking the backend. An error returned after any request reached
// the process must not be marked, even one that timed out: the process may
// have acted on the request. The error reads as err does, and errors.Is and
// errors.As see through it. A nil err stays nil.
func NotSent(err error) error {
	if err == nil {
		return nil
	}
	return &notSentError{err: err}
}

// PolicyNotSent reports whether err, returned by ApplyPolicy, was marked
// with NotSent.
func PolicyNotSent(err error) bool {
	var notSent *notSentError
	return errors.As(err, &notSent)
}
