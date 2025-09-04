package configmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTopicTemplates(t *testing.T) {
	templates := DefaultTopicTemplates()

	assert.Equal(t, "/orgs/{org_id}/agents/{agent_id}/heartbeat", templates.Heartbeat)
	assert.Equal(t, "/orgs/{org_id}/agents/{agent_id}/capabilities", templates.Capabilities)
	assert.Equal(t, "/orgs/{org_id}/agents/{agent_id}/inbox", templates.Inbox)
	assert.Equal(t, "/orgs/{org_id}/agents/{agent_id}/outbox", templates.Outbox)
}

func TestFillTopicTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		claims   *TopicClaims
		expected string
	}{
		{
			name:     "basic substitution",
			template: "/orgs/{org_id}/agents/{agent_id}/test",
			claims: &TopicClaims{
				OrgID:   "org123",
				AgentID: "agent-456",
			},
			expected: "/orgs/org123/agents/agent-456/test",
		},
		{
			name:     "multiple occurrences",
			template: "{org_id}/data/{org_id}/{agent_id}",
			claims: &TopicClaims{
				OrgID:   "company1",
				AgentID: "agent-789",
			},
			expected: "company1/data/company1/agent-789",
		},
		{
			name:     "no placeholders",
			template: "static/topic/name",
			claims: &TopicClaims{
				OrgID:   "org123",
				AgentID: "agent-456",
			},
			expected: "static/topic/name",
		},
		{
			name:     "empty claims",
			template: "/orgs/{org_id}/agents/{agent_id}/test",
			claims: &TopicClaims{
				OrgID:   "",
				AgentID: "",
			},
			expected: "/orgs//agents//test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fillTopicTemplate(tt.template, tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseJWTClaims(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		expectedErr string
		expected    *JWTClaims
	}{
		{
			name:        "empty token",
			tokenString: "",
			expectedErr: "empty token string",
		},
		{
			name:        "invalid JWT format",
			tokenString: "not.a.jwt",
			expectedErr: "failed to parse JWT token",
		},
		{
			name: "valid JWT with org_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"org_id":   "test-org",
				"agent_id": "test-agent-123",
				"iat":      1516239022,
			}),
			expected: &JWTClaims{
				OrgID: "test-org",
			},
		},
		{
			name: "JWT missing org_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"agent_id": "test-agent-123",
				"iat":      1516239022,
			}),
			expectedErr: "org_id claim not found",
		},
		{
			name: "JWT with non-string org_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"org_id":   123,
				"agent_id": "test-agent-123",
				"iat":      1516239022,
			}),
			expectedErr: "org_id claim not found or not a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := parseJWTClaims(tt.tokenString)

			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, claims)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, claims)
			}
		})
	}
}

func TestGenerateTopicsFromTemplate(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		orgID       string
		expected    *tokenResponseTopics
	}{
		{
			name: "valid token generates correct topics",
			tokenString: rawJWTWithClaims(map[string]any{
				"org_id":   "test-org",
				"agent_id": "test-agent-123",
				"iat":      1516239022,
			}),
			orgID: "test-org",
			expected: &tokenResponseTopics{
				Heartbeat:    "/orgs/test-org/agents/test-agent-123/heartbeat",
				Capabilities: "/orgs/test-org/agents/test-agent-123/capabilities",
				Inbox:        "/orgs/test-org/agents/test-agent-123/inbox",
				Outbox:       "/orgs/test-org/agents/test-agent-123/outbox",
			},
		},
		{
			name: "different org and agent values",
			tokenString: rawJWTWithClaims(map[string]any{
				"org_id":   "prod-company",
				"agent_id": "agent-456",
				"iat":      1516239022,
			}),
			orgID: "prod-company",
			expected: &tokenResponseTopics{
				Heartbeat:    "/orgs/prod-company/agents/test-agent-123/heartbeat",
				Capabilities: "/orgs/prod-company/agents/test-agent-123/capabilities",
				Inbox:        "/orgs/prod-company/agents/test-agent-123/inbox",
				Outbox:       "/orgs/prod-company/agents/test-agent-123/outbox",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topics, err := generateTopicsFromTemplate(tt.tokenString, "test-agent-123", &JWTClaims{OrgID: tt.orgID})

			require.NoError(t, err)
			assert.Equal(t, tt.expected, topics)
		})
	}
}

func TestJWTClaimsStruct(t *testing.T) {
	claims := JWTClaims{
		OrgID: "test-org-id",
	}

	assert.Equal(t, "test-org-id", claims.OrgID)
}

func TestTopicTemplatesStruct(t *testing.T) {
	templates := TopicTemplates{
		Heartbeat:    "custom/heartbeat/{org_id}",
		Capabilities: "custom/capabilities/{agent_id}",
		Inbox:        "custom/inbox",
		Outbox:       "custom/outbox",
	}

	assert.Equal(t, "custom/heartbeat/{org_id}", templates.Heartbeat)
	assert.Equal(t, "custom/capabilities/{agent_id}", templates.Capabilities)
	assert.Equal(t, "custom/inbox", templates.Inbox)
	assert.Equal(t, "custom/outbox", templates.Outbox)
}
