package policymgr_test

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// addressInUse is the refusal pktvisord answers for a flow policy whose
// address and port overlap a listener that is already running.
func addressInUse(name string) error {
	return &backend.HTTPError{StatusCode: 409, Message: "409 policy [" + name +
		"] failed to start: unable to bind flow UDP server on 0.0.0.0:6343: address already in use"}
}

// retryingBackend is a mock backend that reports a refusal for an address in
// use as one another of its policies causes, as pktvisor does.
type retryingBackend struct{ *mockBackend }

func (b retryingBackend) RetryAfterRemoval(reason string) bool {
	return strings.Contains(reason, "address already in use")
}

// addressFixture registers a running mock backend under name, as a
// backend.RemovalRetrier, and returns the mock with a policy manager that
// applies to it at once.
func addressFixture(t *testing.T, name string) (*mockBackend, policymgr.PolicyManager) {
	t.Helper()
	be := &mockBackend{name: name}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register(name, retryingBackend{be})
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	return be, mgr
}

// applied returns the names of the policies applied to be, in order.
func applied(be *mockBackend) []string {
	var names []string
	for _, c := range be.Calls {
		if c.Method == "ApplyPolicy" {
			names = append(names, c.Arguments.Get(0).(policies.PolicyData).Name)
		}
	}
	return names
}

func manage(mgr policymgr.PolicyManager, beName, id string) {
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: id, Name: id, Backend: beName, DatasetID: "ds-" + id, Version: 1, Data: map[string]any{}})
}

func stored(t *testing.T, mgr policymgr.PolicyManager, id string) policies.PolicyData {
	t.Helper()
	p, err := mgr.GetRepo().Get(id)
	require.NoError(t, err)
	return p
}

// A flow policy the backend refused because another policy's listener held
// its port, as the backend reports it (backend.RemovalRetrier), is applied
// again once that policy is removed, whichever way it is removed: nothing
// else would apply it again, and it would stay failed with a reason that no
// longer holds. A policy refused for another reason is not.
func TestRemovingAPolicyAppliesAgainThePoliciesRefusedForAnAddressInUse(t *testing.T) {
	for name, remove := range map[string]func(mgr policymgr.PolicyManager, beName string, be backend.Backend){
		"remove": func(mgr policymgr.PolicyManager, beName string, _ backend.Backend) {
			require.NoError(t, mgr.RemovePolicy("sflow", "sflow", beName))
		},
		"remove action": func(mgr policymgr.PolicyManager, beName string, _ backend.Backend) {
			mgr.ManagePolicy(config.PolicyPayload{Action: "remove", ID: "sflow", Name: "sflow", Backend: beName})
		},
		"last dataset": func(mgr policymgr.PolicyManager, beName string, be backend.Backend) {
			mgr.RemovePolicyDataset("sflow", "ds-sflow", beName, retryingBackend{be.(*mockBackend)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			beName := "address_in_use_" + map[string]string{"remove": "a", "remove action": "b", "last dataset": "c"}[name]
			be, mgr := addressFixture(t, beName)
			be.On("ApplyPolicy", isPolicy("sflow", 1), false).Return(nil).Once()
			manage(mgr, beName, "sflow")
			be.On("ApplyPolicy", isPolicy("netflow", 1), false).Return(addressInUse("netflow")).Once()
			manage(mgr, beName, "netflow")
			be.On("ApplyPolicy", isPolicy("invalid", 1), false).Return(&backend.HTTPError{StatusCode: 422, Message: "422 invalid flow config"}).Once()
			manage(mgr, beName, "invalid")
			require.Contains(t, stored(t, mgr, "netflow").BackendErr, "address already in use")

			be.On("RemovePolicy", isPolicy("sflow", 1)).Return(nil).Once()
			be.On("ApplyPolicy", isPolicy("netflow", 1), true).Return(nil).Once()
			remove(mgr, beName, be)

			be.AssertExpectations(t)
			assert.Equal(t, []string{"sflow", "netflow", "invalid", "netflow"}, applied(be))
			netflow := stored(t, mgr, "netflow")
			assert.Equal(t, policies.Running, netflow.State)
			assert.Empty(t, netflow.BackendErr, "the reason that no longer holds is cleared")
			assert.Equal(t, policies.FailedToApply, stored(t, mgr, "invalid").State, "a policy refused for another reason is not applied again")
		})
	}
}

// When two refused policies ask for the port freed, they are applied in name
// order: the first gets it, and the other is refused again, with a fresh
// reason.
func TestPoliciesRefusedForAnAddressInUseAreAppliedAgainInNameOrder(t *testing.T) {
	be, mgr := addressFixture(t, "address_in_use_order")
	be.On("ApplyPolicy", isPolicy("sflow", 1), false).Return(nil).Once()
	manage(mgr, "address_in_use_order", "sflow")
	for _, id := range []string{"netflow-b", "netflow-a"} {
		be.On("ApplyPolicy", isPolicy(id, 1), false).Return(addressInUse(id)).Once()
		manage(mgr, "address_in_use_order", id)
	}

	be.On("RemovePolicy", isPolicy("sflow", 1)).Return(nil).Once()
	be.On("ApplyPolicy", isPolicy("netflow-a", 1), true).Return(nil).Once()
	be.On("ApplyPolicy", isPolicy("netflow-b", 1), true).Return(addressInUse("netflow-b")).Once()
	require.NoError(t, mgr.RemovePolicy("sflow", "sflow", "address_in_use_order"))

	be.AssertExpectations(t)
	assert.Equal(t, []string{"sflow", "netflow-b", "netflow-a", "netflow-a", "netflow-b"}, applied(be))
	assert.Equal(t, policies.Running, stored(t, mgr, "netflow-a").State)
	b := stored(t, mgr, "netflow-b")
	assert.Equal(t, policies.FailedToApply, b.State)
	assert.Contains(t, b.BackendErr, "address already in use")
}

// Nothing is applied again when the policy removed held nothing: one the
// backend refused itself, or one whose removal the backend failed, which may
// still hold its port.
func TestRemovingAPolicyThatHeldNothingAppliesNothingAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		removed   string
		removeErr error
	}{
		"a refused policy":  {removed: "netflow-b", removeErr: nil},
		"a failed removal":  {removed: "sflow", removeErr: errors.New("connection refused")},
		"a policy not here": {removed: "sflow", removeErr: &backend.HTTPError{StatusCode: 404, Message: "404 policy does not exists"}},
	} {
		t.Run(name, func(t *testing.T) {
			beName := "address_in_use_nothing_" + map[string]string{"a refused policy": "a", "a failed removal": "b", "a policy not here": "c"}[name]
			be, mgr := addressFixture(t, beName)
			be.On("ApplyPolicy", isPolicy("sflow", 1), false).Return(nil).Once()
			manage(mgr, beName, "sflow")
			for _, id := range []string{"netflow-a", "netflow-b"} {
				be.On("ApplyPolicy", isPolicy(id, 1), false).Return(addressInUse(id)).Once()
				manage(mgr, beName, id)
			}

			be.On("RemovePolicy", isPolicy(tc.removed, 1)).Return(tc.removeErr).Once()
			require.NoError(t, mgr.RemovePolicy(tc.removed, tc.removed, beName))

			be.AssertExpectations(t)
			assert.Equal(t, []string{"sflow", "netflow-a", "netflow-b"}, applied(be), "nothing applied again")
		})
	}
}

// A backend that does not report which refusals another policy causes gets
// nothing applied again: the policy manager does not read its reasons itself.
func TestRemovingAPolicyAppliesNothingAgainOnABackendThatReportsNoSuchRefusal(t *testing.T) {
	be := &mockBackend{name: "address_in_use_no_retrier"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("address_in_use_no_retrier", be)
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	be.On("ApplyPolicy", isPolicy("sflow", 1), false).Return(nil).Once()
	manage(mgr, "address_in_use_no_retrier", "sflow")
	be.On("ApplyPolicy", isPolicy("netflow", 1), false).Return(addressInUse("netflow")).Once()
	manage(mgr, "address_in_use_no_retrier", "netflow")

	be.On("RemovePolicy", isPolicy("sflow", 1)).Return(nil).Once()
	require.NoError(t, mgr.RemovePolicy("sflow", "sflow", "address_in_use_no_retrier"))

	be.AssertExpectations(t)
	assert.Equal(t, []string{"sflow", "netflow"}, applied(be))
	assert.Equal(t, policies.FailedToApply, stored(t, mgr, "netflow").State)
}
