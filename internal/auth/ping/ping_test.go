// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ping_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/genai-toolbox/internal/auth/ping"
)

func TestAuthServiceType(t *testing.T) {
	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://example.com",
		ClientID: "test-client-id",
	}

	if got := cfg.AuthServiceConfigType(); got != ping.AuthServiceType {
		t.Errorf("AuthServiceConfigType() = %q, want %q", got, ping.AuthServiceType)
	}
}

// setupTestServer creates a test server that serves OIDC discovery and JWKS endpoints
func setupTestServer(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	// Create JWK from private key
	jwk := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	mux := http.NewServeMux()

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// We'll update the jwks_uri in the test
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": "", // Will be set dynamically
		})
	})

	return httptest.NewServer(mux)
}

// createTestToken creates a signed JWT token for testing
func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", "test-key-id"))
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return token
}

func TestGetClaimsFromHeader_ValidToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create JWK from private key
	jwk := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	// Create test server
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create auth service with explicit JWKS URL
	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "test-client-id",
		JwksURL:  server.URL + "/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	// Create valid token
	claims := map[string]interface{}{
		"iss":       "https://idpb2e.adeo.com",
		"client_id": "test-client-id",
		"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
		"uid":       "12345",
		"usertype":  "WORKER",
		"scope":     []string{"openid", "profile", "email"},
	}

	token := createTestToken(t, privateKey, claims)

	// Test with Authorization: Bearer header
	t.Run("Authorization Bearer header", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "Bearer "+token)

		gotClaims, err := authService.GetClaimsFromHeader(context.Background(), header)
		if err != nil {
			t.Fatalf("GetClaimsFromHeader() error = %v", err)
		}

		if gotClaims["uid"] != "12345" {
			t.Errorf("GetClaimsFromHeader() uid = %v, want %v", gotClaims["uid"], "12345")
		}
		if gotClaims["usertype"] != "WORKER" {
			t.Errorf("GetClaimsFromHeader() usertype = %v, want %v", gotClaims["usertype"], "WORKER")
		}
	})

	// Test with {name}_token header
	t.Run("name_token header", func(t *testing.T) {
		header := http.Header{}
		header.Set("test-ping_token", token)

		gotClaims, err := authService.GetClaimsFromHeader(context.Background(), header)
		if err != nil {
			t.Fatalf("GetClaimsFromHeader() error = %v", err)
		}

		if gotClaims["uid"] != "12345" {
			t.Errorf("GetClaimsFromHeader() uid = %v, want %v", gotClaims["uid"], "12345")
		}
	})
}

func TestGetClaimsFromHeader_NoToken(t *testing.T) {
	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "test-client-id",
		JwksURL:  "http://localhost/jwks", // Won't be called
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	header := http.Header{}

	claims, err := authService.GetClaimsFromHeader(context.Background(), header)
	if err != nil {
		t.Errorf("GetClaimsFromHeader() error = %v, want nil", err)
	}
	if claims != nil {
		t.Errorf("GetClaimsFromHeader() claims = %v, want nil", claims)
	}
}

func TestGetClaimsFromHeader_InvalidIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://expected-issuer.com",
		ClientID: "test-client-id",
		JwksURL:  server.URL + "/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	// Token with wrong issuer
	claims := map[string]interface{}{
		"iss":       "https://wrong-issuer.com",
		"client_id": "test-client-id",
		"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := createTestToken(t, privateKey, claims)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	_, err = authService.GetClaimsFromHeader(context.Background(), header)
	if err == nil {
		t.Error("GetClaimsFromHeader() expected error for invalid issuer, got nil")
	}
}

func TestGetClaimsFromHeader_InvalidClientID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "expected-client-id",
		JwksURL:  server.URL + "/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	// Token with wrong client_id
	claims := map[string]interface{}{
		"iss":       "https://idpb2e.adeo.com",
		"client_id": "wrong-client-id",
		"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := createTestToken(t, privateKey, claims)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	_, err = authService.GetClaimsFromHeader(context.Background(), header)
	if err == nil {
		t.Error("GetClaimsFromHeader() expected error for invalid client_id, got nil")
	}
}

func TestGetClaimsFromHeader_ExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "test-client-id",
		JwksURL:  server.URL + "/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	// Expired token
	claims := map[string]interface{}{
		"iss":       "https://idpb2e.adeo.com",
		"client_id": "test-client-id",
		"exp":       float64(time.Now().Add(-1 * time.Hour).Unix()), // Expired 1 hour ago
	}

	token := createTestToken(t, privateKey, claims)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	_, err = authService.GetClaimsFromHeader(context.Background(), header)
	if err == nil {
		t.Error("GetClaimsFromHeader() expected error for expired token, got nil")
	}
}

func TestGetName(t *testing.T) {
	cfg := ping.Config{
		Name:     "my-ping-service",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "test-client-id",
		JwksURL:  "http://localhost/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	if got := authService.GetName(); got != "my-ping-service" {
		t.Errorf("GetName() = %q, want %q", got, "my-ping-service")
	}
}

func TestToConfig(t *testing.T) {
	cfg := ping.Config{
		Name:     "test-ping",
		Type:     ping.AuthServiceType,
		Issuer:   "https://idpb2e.adeo.com",
		ClientID: "test-client-id",
		JwksURL:  "http://localhost/jwks",
	}

	authService, err := cfg.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize auth service: %v", err)
	}

	gotCfg := authService.ToConfig()
	if diff := cmp.Diff(cfg, gotCfg); diff != "" {
		t.Errorf("ToConfig() mismatch (-want +got):\n%s", diff)
	}
}
