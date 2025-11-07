package fleet

import "testing"

func TestGenerateTopicsFromTemplate_IncludesIngest(t *testing.T) {
	claims := &JWTClaims{OrgID: "org-123", AgentID: "agent-abc"}
	topics, err := GenerateTopicsFromTemplate(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "orgs/org-123/agents/agent-abc/ingest"
	if topics.Ingest != expected {
		t.Fatalf("expected ingest topic %q, got %q", expected, topics.Ingest)
	}
}
