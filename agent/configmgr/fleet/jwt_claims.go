package fleet

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// jwtParseSignatureAlgorithms lists algorithms allowed when parsing tokens from the
// OAuth token endpoint. EdDSA matches orb-auth (Ed25519 / isc-jwt); others cover common IdPs.
var jwtParseSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.HS256, jose.HS384, jose.HS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// JWTClaims represents the JWT claims we extract for topic templating
type JWTClaims struct {
	AgentID  string
	OrgID    string
	Zone     string
	ClientID string
	MqttURL  string
}

// ParseJWTClaims extracts org_id claim from a JWT token
func ParseJWTClaims(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token string")
	}

	// Parse the JWT token without verification (since we already trust it from the token endpoint)
	token, err := jwt.ParseSigned(tokenString, jwtParseSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	var claims jwt.Claims
	var customClaims map[string]any

	// Extract both standard and custom claims without verification
	if err := token.UnsafeClaimsWithoutVerification(&claims, &customClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	// Extract org_id from custom claims
	jwtClaims := &JWTClaims{}

	if orgID, ok := customClaims["orb:org_id"].(string); ok {
		jwtClaims.OrgID = orgID
	} else {
		return nil, fmt.Errorf("orb:org_id claim not found or not a string in JWT token")
	}
	if zone, ok := customClaims["orb:zone"].(string); ok {
		jwtClaims.Zone = zone
	} else {
		return nil, fmt.Errorf("orb:zone claim not found or not a string in JWT token")
	}
	if clientID, ok := customClaims["client_id"].(string); ok {
		jwtClaims.ClientID = clientID
	} else {
		return nil, fmt.Errorf("client_id claim not found or not a string in JWT token")
	}
	if agentID, ok := customClaims["orb:agent_id"].(string); ok {
		jwtClaims.AgentID = agentID
	} else {
		return nil, fmt.Errorf("orb:agent_id claim not found or not a string in JWT token")
	}

	if extClaims, ok := customClaims["ext"].(map[string]any); ok {
		if mqttURL, ok := extClaims["orb:mqtt_url"].(string); ok {
			jwtClaims.MqttURL = mqttURL
		}
	}

	return jwtClaims, nil
}
