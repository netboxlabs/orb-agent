package configmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFillTopicTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		claims   *JWTClaims
		expected string
	}{
		{
			name:     "basic substitution",
			template: "/orgs/{org_id}/agents/{agent_id}/test",
			claims: &JWTClaims{
				OrgID:   "org123",
				AgentID: "agent-456",
			},
			expected: "/orgs/org123/agents/agent-456/test",
		},
		{
			name:     "multiple occurrences",
			template: "{org_id}/data/{org_id}/{agent_id}",
			claims: &JWTClaims{
				OrgID:   "company1",
				AgentID: "agent-789",
			},
			expected: "company1/data/company1/agent-789",
		},
		{
			name:     "no placeholders",
			template: "static/topic/name",
			claims: &JWTClaims{
				OrgID:   "org123",
				AgentID: "agent-456",
			},
			expected: "static/topic/name",
		},
		{
			name:     "empty claims",
			template: "/orgs/{org_id}/agents/{agent_id}/test",
			claims: &JWTClaims{
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
				"orb:org_id":   "test-org",
				"orb:zone":     "default",
				"orb:agent_id": "test-agent",
				"client_id":    "test-client",
				"iat":          1516239022,
				"ext": map[string]any{
					"orb:mqtt_url": "mqtt://test.example.com:1883",
				},
			}),
			expected: &JWTClaims{
				OrgID:    "test-org",
				Zone:     "default",
				ClientID: "test-client",
				AgentID:  "test-agent",
				MqttURL:  "mqtt://test.example.com:1883",
			},
		},
		{
			name: "JWT missing org_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"client_id":    "test-client",
				"iat":          1516239022,
				"orb:agent_id": "test-agent",
				"orb:zone":     "default",
			}),
			expectedErr: "orb:org_id claim not found",
		},
		{
			name: "JWT with non-string org_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"orb:org_id":   123,
				"orb:zone":     "default",
				"client_id":    "test-client",
				"iat":          1516239022,
				"orb:agent_id": "test-agent",
			}),
			expectedErr: "orb:org_id claim not found or not a string",
		},
		{
			name: "JWT missing agent_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"client_id":  "test-client",
				"iat":        1516239022,
				"orb:org_id": "test-org",
				"orb:zone":   "default",
			}),
			expectedErr: "orb:agent_id claim not found",
		},
		{
			name: "JWT with non-string agent_id",
			tokenString: rawJWTWithClaims(map[string]any{
				"orb:agent_id": 123,
				"orb:zone":     "default",
				"client_id":    "test-client",
				"iat":          1516239022,
				"orb:org_id":   "test-org",
			}),
			expectedErr: "orb:agent_id claim not found or not a string",
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
		name     string
		orgID    string
		agentID  string
		expected *tokenResponseTopics
	}{
		{
			name:    "valid token generates correct topics",
			orgID:   "test-org",
			agentID: "test-client-123",
			expected: &tokenResponseTopics{
				Heartbeat:    "orgs/test-org/agents/test-client-123/heartbeats",
				Capabilities: "orgs/test-org/agents/test-client-123/capabilities",
				Inbox:        "orgs/test-org/agents/test-client-123/inbox",
				Outbox:       "orgs/test-org/agents/test-client-123/outbox",
			},
		},
		{
			name:    "different org and agent values",
			orgID:   "prod-company",
			agentID: "test-agent-123",
			expected: &tokenResponseTopics{
				Heartbeat:    "orgs/prod-company/agents/test-agent-123/heartbeats",
				Capabilities: "orgs/prod-company/agents/test-agent-123/capabilities",
				Inbox:        "orgs/prod-company/agents/test-agent-123/inbox",
				Outbox:       "orgs/prod-company/agents/test-agent-123/outbox",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topics, err := generateTopicsFromTemplate(&JWTClaims{OrgID: tt.orgID, AgentID: tt.agentID})

			require.NoError(t, err)
			assert.Equal(t, tt.expected, topics)
		})
	}
}
