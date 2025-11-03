package fleet

import "github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"

// GroupRetriever provides read-only access to group memberships
type GroupRetriever interface {
	GetAll() []messages.GroupMembershipData
}

// GroupManager manages the agent's group memberships
type GroupManager struct {
	groups []messages.GroupMembershipData
}

func newGroupManager() GroupManager {
	return GroupManager{
		groups: []messages.GroupMembershipData{},
	}
}

// Add adds a group to the manager
func (gm *GroupManager) Add(group messages.GroupMembershipData) {
	gm.groups = append(gm.groups, group)
}

// RemoveAll removes all groups from the manager
func (gm *GroupManager) RemoveAll() {
	gm.groups = []messages.GroupMembershipData{}
}

// Remove removes a specific group by ID from the manager
func (gm *GroupManager) Remove(groupID string) {
	for i, group := range gm.groups {
		if group.GroupID == groupID {
			gm.groups = append(gm.groups[:i], gm.groups[i+1:]...)
			break
		}
	}
}

// GetAll returns all groups managed by the manager
func (gm *GroupManager) GetAll() []messages.GroupMembershipData {
	return gm.groups
}
