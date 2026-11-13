package backend

import "errors"

// notSentError marks an error ApplyPolicy returned without having sent the
// policy to the backend's process.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }

func (e *notSentError) Unwrap() error { return e.err }

// NotSent marks err, an error ApplyPolicy returns, as one returned before
// the backend sent the policy to its process, such as a policy the backend
// refuses to send: the process holds no more of the policy than it did
// before the call. The policy manager then keeps what it knew before the
// call, so a policy that never reached the backend is still applied fresh
// next time. The error reads as err does, and errors.Is and errors.As see
// through it. A nil err stays nil.
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
