package fleet

import (
	"strings"
)

// fillTopicTemplate replaces placeholders in a topic template with actual values
func fillTopicTemplate(template string, claims *JWTClaims) string {
	result := template
	result = strings.ReplaceAll(result, "{org_id}", claims.OrgID)
	result = strings.ReplaceAll(result, "{agent_id}", claims.AgentID)
	return result
}

const (
	heartbeatTemplate    = "orgs/{org_id}/agents/{agent_id}/heartbeats"
	capabilitiesTemplate = "orgs/{org_id}/agents/{agent_id}/capabilities"
	inboxTemplate        = "orgs/{org_id}/agents/{agent_id}/inbox"
	outboxTemplate       = "orgs/{org_id}/agents/{agent_id}/outbox"
	otlpTemplate         = "orgs/{org_id}/agents/{agent_id}/otlp"

	groupsTemplate = "orgs/{org_id}/groups/{group_id}"
)

// TokenResponseTopics are the topics extracted from the JWT claims
type TokenResponseTopics struct {
	Heartbeat    string `json:"heartbeat"`
	Capabilities string `json:"capabilities"`
	Inbox        string `json:"inbox"`
	Outbox       string `json:"outbox"`
	OTLP         string `json:"otlp"`
}

// GenerateTopicsFromTemplate creates actual topic names from templates using JWT claims and config agent_id
func GenerateTopicsFromTemplate(jwtClaims *JWTClaims) (*TokenResponseTopics, error) {
	return &TokenResponseTopics{
		Heartbeat:    fillTopicTemplate(heartbeatTemplate, jwtClaims),
		Capabilities: fillTopicTemplate(capabilitiesTemplate, jwtClaims),
		Inbox:        fillTopicTemplate(inboxTemplate, jwtClaims),
		Outbox:       fillTopicTemplate(outboxTemplate, jwtClaims),
		OTLP:         fillTopicTemplate(otlpTemplate, jwtClaims),
	}, nil
}

func groupTopic(orgID, groupID string) string {
	result := strings.ReplaceAll(groupsTemplate, "{org_id}", orgID)
	result = strings.ReplaceAll(result, "{group_id}", groupID)
	return result
}
