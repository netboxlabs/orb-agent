package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func TestGroupManager_Add_SingleGroup(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	group := messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	}

	// Act
	gm.Add(group)

	// Assert
	groups := gm.GetAll()
	require.Len(t, groups, 1)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "Test Group 1", groups[0].Name)
}

func TestGroupManager_Add_Groups(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	group1 := messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	}
	group2 := messages.GroupMembershipData{
		GroupID: "group-2",
		Name:    "Test Group 2",
	}
	group3 := messages.GroupMembershipData{
		GroupID: "group-3",
		Name:    "Test Group 3",
	}

	// Act
	gm.Add(group1)
	gm.Add(group2)
	gm.Add(group3)

	// Assert
	groups := gm.GetAll()
	require.Len(t, groups, 3)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-2", groups[1].GroupID)
	assert.Equal(t, "group-3", groups[2].GroupID)
}

func TestGroupManager_Add_DuplicateGroups(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	group1 := messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	}
	group2 := messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	}

	// Act
	gm.Add(group1)
	gm.Add(group2)

	// Assert - Add allows duplicates (no deduplication)
	groups := gm.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-1", groups[1].GroupID)
}

func TestGroupManager_GetAll_EmptyGroups(t *testing.T) {
	// Arrange
	gm := newGroupManager()

	// Act
	groups := gm.GetAll()

	// Assert
	assert.NotNil(t, groups)
	assert.Empty(t, groups)
}

func TestGroupManager_RemoveAll_Success(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-3", Name: "Test Group 3", ChannelID: "channel-3"})

	// Verify groups were added
	require.Len(t, gm.GetAll(), 3)

	// Act
	gm.RemoveAll()

	// Assert
	groups := gm.GetAll()
	assert.NotNil(t, groups)
	assert.Empty(t, groups)
}

func TestGroupManager_Remove_SingleGroup(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-3", Name: "Test Group 3", ChannelID: "channel-3"})

	// Act
	gm.Remove("group-2")

	// Assert
	groups := gm.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-3", groups[1].GroupID)
}

func TestGroupManager_Remove_FirstGroup(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-3", Name: "Test Group 3", ChannelID: "channel-3"})

	// Act
	gm.Remove("group-1")

	// Assert
	groups := gm.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-2", groups[0].GroupID)
	assert.Equal(t, "group-3", groups[1].GroupID)
}

func TestGroupManager_Remove_LastGroup(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-3", Name: "Test Group 3", ChannelID: "channel-3"})

	// Act
	gm.Remove("group-3")

	// Assert
	groups := gm.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-2", groups[1].GroupID)
}

func TestGroupManager_Remove_NonExistentGroup(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})

	// Act - Remove non-existent group should not panic
	gm.Remove("group-999")

	// Assert - No change in groups
	groups := gm.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-2", groups[1].GroupID)
}

func TestGroupManager_GroupRetrieverInterface(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Test Group 1", ChannelID: "channel-1"})
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Test Group 2", ChannelID: "channel-2"})

	// Act - Use as GroupRetriever interface
	var retriever GroupRetriever = &gm

	// Assert
	groups := retriever.GetAll()
	require.Len(t, groups, 2)
	assert.Equal(t, "group-1", groups[0].GroupID)
	assert.Equal(t, "group-2", groups[1].GroupID)
}
