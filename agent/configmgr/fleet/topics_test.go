package fleet

import "testing"

func TestGenerateTopicsFromTemplate_IncludesOTLP(t *testing.T) {
	claims := &JWTClaims{OrgID: "org-123", AgentID: "agent-abc"}
	topics, err := GenerateTopicsFromTemplate(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "orgs/org-123/agents/agent-abc/otlp"
	if topics.OTLP != expected {
		t.Fatalf("expected OTLP topic %q, got %q", expected, topics.OTLP)
	}
}
