package configmgr

import (
	"strings"
)

// JWTClaims represents the JWT claims we extract for topic templating
type JWTClaims struct {
	OrgID string `json:"orb:org_id"`
	Zone  string `json:"orb:zone"`
}

// TopicClaims combines org_id from JWT with agent_id from config
type TopicClaims struct {
	OrgID    string
	ClientId string
}

// TopicTemplates defines hardcoded topic name patterns with placeholders
type TopicTemplates struct {
	Heartbeat    string
	Capabilities string
	Inbox        string
	Outbox       string
}

// DefaultTopicTemplates returns the hardcoded topic templates
func DefaultTopicTemplates() TopicTemplates {
	return TopicTemplates{
		Heartbeat:    "orgs/{org_id}/agents/{client_id}/heartbeat",
		Capabilities: "orgs/{org_id}/agents/{client_id}/capabilities",
		Inbox:        "orgs/{org_id}/agents/{client_id}/inbox",
		Outbox:       "orgs/{org_id}/agents/{client_id}/outbox",
	}
}

// fillTopicTemplate replaces placeholders in a topic template with actual values
func fillTopicTemplate(template string, claims *TopicClaims) string {
	result := template
	result = strings.ReplaceAll(result, "{org_id}", claims.OrgID)
	result = strings.ReplaceAll(result, "{client_id}", claims.ClientId)
	return result
}

// generateTopicsFromTemplate creates actual topic names from templates using JWT claims and config agent_id
func generateTopicsFromTemplate(tokenString string, clientID string, jwtClaims *JWTClaims) (*tokenResponseTopics, error) {
	// Combine JWT org_id with config agent_id
	topicClaims := &TopicClaims{
		OrgID:    jwtClaims.OrgID,
		ClientId: clientID,
	}

	templates := DefaultTopicTemplates()

	topics := &tokenResponseTopics{
		Heartbeat:    fillTopicTemplate(templates.Heartbeat, topicClaims),
		Capabilities: fillTopicTemplate(templates.Capabilities, topicClaims),
		Inbox:        fillTopicTemplate(templates.Inbox, topicClaims),
		Outbox:       fillTopicTemplate(templates.Outbox, topicClaims),
	}

	return topics, nil
}
