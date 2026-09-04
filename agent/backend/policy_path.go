package backend

import (
	"fmt"
	neturl "net/url"
	"strings"
)

// PolicyPathSegment renders a policy name as one path segment of a backend's
// API URL.
//
// Policy names are operator-written and forwarded verbatim, so a name may
// carry any character. Left raw, several of them never reach the backend:
// "#" is read as a fragment and "?" as a query, so the request lands on a
// truncated name, and "%" does not parse as a URL at all. Percent-escaping
// settles those.
//
// A "/" is the exception escaping cannot settle, and it is refused instead.
// The receiving frameworks decode percent-escapes before routing (the ASGI
// spec requires it), so "%2F" becomes a separator again on arrival. A
// trailing one then earns a 307 to the route without it, which the Go client
// follows with the method intact, deleting a different policy and reporting
// success. Failing here is the only outcome that does not act on the wrong
// policy.
func PolicyPathSegment(name string) (string, error) {
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("policy name %q contains a slash, which cannot address a single policy over the backend API; rename the policy", name)
	}
	return neturl.PathEscape(name), nil
}
