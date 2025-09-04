package configmgr

import (
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWTClaims represents the JWT claims we extract for topic templating
type JWTClaims struct {
	OrgID string `json:"org_id"`
}

// TopicClaims combines org_id from JWT with agent_id from config
type TopicClaims struct {
	OrgID   string
	AgentID string
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
		Heartbeat:    "/orgs/{org_id}/agents/{agent_id}/heartbeat",
		Capabilities: "/orgs/{org_id}/agents/{agent_id}/capabilities",
		Inbox:        "/orgs/{org_id}/agents/{agent_id}/inbox",
		Outbox:       "/orgs/{org_id}/agents/{agent_id}/outbox",
	}
}

// parseJWTClaims extracts org_id claim from a JWT token
func parseJWTClaims(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token string")
	}

	// Parse the JWT token without verification (since we already trust it from the token endpoint)
	// We accept common signature algorithms used in JWTs
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	var claims jwt.Claims
	var customClaims map[string]interface{}

	// Extract both standard and custom claims without verification
	if err := token.UnsafeClaimsWithoutVerification(&claims, &customClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	// Extract org_id from custom claims
	jwtClaims := &JWTClaims{}

	if orgID, ok := customClaims["org_id"].(string); ok {
		jwtClaims.OrgID = orgID
	} else {
		return nil, fmt.Errorf("org_id claim not found or not a string in JWT token")
	}

	return jwtClaims, nil
}

// fillTopicTemplate replaces placeholders in a topic template with actual values
func fillTopicTemplate(template string, claims *TopicClaims) string {
	result := template
	result = strings.ReplaceAll(result, "{org_id}", claims.OrgID)
	result = strings.ReplaceAll(result, "{agent_id}", claims.AgentID)
	return result
}

// generateTopicsFromTemplate creates actual topic names from templates using JWT claims and config agent_id
func generateTopicsFromTemplate(tokenString string, agentID string) (*tokenResponseTopics, error) {
	jwtClaims, err := parseJWTClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Combine JWT org_id with config agent_id
	topicClaims := &TopicClaims{
		OrgID:   jwtClaims.OrgID,
		AgentID: agentID,
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
