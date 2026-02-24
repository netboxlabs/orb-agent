package fleet

import (
	"sync"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

// GroupRetriever provides read-only access to group memberships
type GroupRetriever interface {
	GetAll() []messages.GroupMembershipData
}

// GroupManager manages the agent's group memberships
type GroupManager struct {
	mu     sync.RWMutex
	groups []messages.GroupMembershipData
}

func newGroupManager() GroupManager {
	return GroupManager{
		groups: []messages.GroupMembershipData{},
	}
}

// Add adds a group to the manager
func (gm *GroupManager) Add(group messages.GroupMembershipData) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.groups = append(gm.groups, group)
}

// RemoveAll removes all groups from the manager
func (gm *GroupManager) RemoveAll() {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.groups = []messages.GroupMembershipData{}
}

// Remove removes a specific group by ID from the manager
func (gm *GroupManager) Remove(groupID string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	for i, group := range gm.groups {
		if group.GroupID == groupID {
			gm.groups = append(gm.groups[:i], gm.groups[i+1:]...)
			break
		}
	}
}

// GetAll returns all groups managed by the manager
// Returns a copy to prevent external mutation
func (gm *GroupManager) GetAll() []messages.GroupMembershipData {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	result := make([]messages.GroupMembershipData, len(gm.groups))
	copy(result, gm.groups)
	return result
}
