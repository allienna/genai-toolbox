// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ping

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/googleapis/genai-toolbox/internal/auth"
)

const AuthServiceType string = "ping"

// validate interface
var _ auth.AuthServiceConfig = Config{}

// Config is the auth service configuration for PingID/PingFederate
type Config struct {
	Name     string `yaml:"name" validate:"required"`
	Type     string `yaml:"type" validate:"required"`
	Issuer   string `yaml:"issuer" validate:"required"`   // e.g., "https://idpb2e.adeo.com"
	ClientID string `yaml:"clientId" validate:"required"` // Expected client_id claim
	JwksURL  string `yaml:"jwksUrl"`                      // Optional: override JWKS URL
}

// AuthServiceConfigType returns the auth service type
func (cfg Config) AuthServiceConfigType() string {
	return AuthServiceType
}

// Initialize creates a PingID auth service
func (cfg Config) Initialize() (auth.AuthService, error) {
	jwksURL := cfg.JwksURL
	if jwksURL == "" {
		// Fetch JWKS URL from OIDC discovery endpoint
		discoveryURL := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
		discoveredJwksURL, err := fetchJwksURLFromDiscovery(discoveryURL)
		if err != nil {
			return nil, fmt.Errorf("failed to discover JWKS URL: %w", err)
		}
		jwksURL = discoveredJwksURL
	}

	a := &AuthService{
		Config:  cfg,
		jwksURL: jwksURL,
	}
	return a, nil
}

// fetchJwksURLFromDiscovery fetches the jwks_uri from the OIDC discovery endpoint
func fetchJwksURLFromDiscovery(discoveryURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", fmt.Errorf("failed to decode OIDC discovery response: %w", err)
	}

	if discovery.JwksURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OIDC discovery response")
	}

	return discovery.JwksURI, nil
}

var _ auth.AuthService = &AuthService{}

// AuthService handles PingID/PingFederate token validation
type AuthService struct {
	Config
	jwksURL string
	jwks    *jose.JSONWebKeySet
	jwksMu  sync.RWMutex
	jwksExp time.Time
}

// AuthServiceType returns the auth service type
func (a *AuthService) AuthServiceType() string {
	return AuthServiceType
}

// ToConfig returns the configuration
func (a *AuthService) ToConfig() auth.AuthServiceConfig {
	return a.Config
}

// GetName returns the name of the auth service
func (a *AuthService) GetName() string {
	return a.Name
}

// GetClaimsFromHeader extracts and validates a PingID token from HTTP headers
// and returns the token's claims if validation succeeds.
//
// The function looks for a token in either:
// 1. Authorization header with "Bearer " prefix (standard OAuth2)
// 2. Header with key "{service_name}_token" (toolbox pattern)
//
// Returns:
// - map[string]any: The claims from the validated token
// - error: nil if successful, error if validation fails
// - (nil, nil): if no token header is found
func (a *AuthService) GetClaimsFromHeader(ctx context.Context, h http.Header) (map[string]any, error) {
	// Try Authorization: Bearer first (standard OAuth2)
	var token string
	if authHeader := h.Get("Authorization"); authHeader != "" {
		if t, found := strings.CutPrefix(authHeader, "Bearer "); found {
			token = t
		}
	}

	// Fall back to {name}_token header (toolbox pattern)
	if token == "" {
		headerKey := a.Name + "_token"
		token = h.Get(headerKey)
	}

	if token == "" {
		return nil, nil
	}

	// Parse the JWT without verification first to get the key ID
	parsedJWT, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("PingID token parse failure: %w", err)
	}

	// Fetch JWKS if needed
	jwks, err := a.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Find the key - try by kid first, then try all keys if not found
	var claims map[string]any
	var verifyErr error

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("PingID token verification failure: no keys in JWKS")
	}

	// Try to find by key ID first
	keysToTry := []jose.JSONWebKey{}
	if len(parsedJWT.Headers) > 0 && parsedJWT.Headers[0].KeyID != "" {
		keysToTry = jwks.Key(parsedJWT.Headers[0].KeyID)
	}

	// If no matching key ID found, try all keys (some IdPs use non-matching kid values)
	if len(keysToTry) == 0 {
		keysToTry = jwks.Keys
	}

	// Try each key until one works
	for _, jwk := range keysToTry {
		claims = make(map[string]any)
		if err := parsedJWT.Claims(jwk.Key, &claims); err == nil {
			verifyErr = nil
			break
		} else {
			verifyErr = err
		}
	}

	if verifyErr != nil {
		return nil, fmt.Errorf("PingID token verification failure: %w", verifyErr)
	}

	// Validate issuer
	if iss, ok := claims["iss"].(string); !ok || iss != a.Issuer {
		return nil, fmt.Errorf("PingID token verification failure: invalid issuer, expected %q, got %q", a.Issuer, iss)
	}

	// Validate client_id
	// if clientID, ok := claims["client_id"].(string); !ok || clientID != a.ClientID {
	// return nil, fmt.Errorf("PingID token verification failure: invalid client_id, expected %q, got %q", a.ClientID, clientID)
	// }

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, fmt.Errorf("PingID token verification failure: token expired")
		}
	}

	return claims, nil
}

// getJWKS returns the cached JWKS or fetches it if expired/missing
func (a *AuthService) getJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	a.jwksMu.RLock()
	if a.jwks != nil && time.Now().Before(a.jwksExp) {
		defer a.jwksMu.RUnlock()
		return a.jwks, nil
	}
	a.jwksMu.RUnlock()

	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	// Double-check after acquiring write lock
	if a.jwks != nil && time.Now().Before(a.jwksExp) {
		return a.jwks, nil
	}

	// Fetch JWKS
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	a.jwks = &jwks
	a.jwksExp = time.Now().Add(1 * time.Hour) // Cache for 1 hour

	return a.jwks, nil
}
