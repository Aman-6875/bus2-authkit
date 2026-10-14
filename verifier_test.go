package authkit_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	authkit "github.com/Aman-6875/bus2-authkit"
)

// newTestIssuer starts a fake JWKS server backed by a freshly generated RSA
// key pair, and returns its URL plus a function to sign tokens with that
// same key — standing in for Hydra in tests.
func newTestIssuer(t *testing.T) (jwksURL string, sign func(claims authkit.Claims) string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	store := jwkset.NewMemoryStorage()
	jwk, err := jwkset.NewJWKFromKey(privateKey.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: "test-key",
			ALG: jwkset.AlgRS256,
		},
	})
	if err != nil {
		t.Fatalf("build JWK: %v", err)
	}
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		t.Fatalf("write JWK: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks, err := store.JSONPublic(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}))
	t.Cleanup(server.Close)

	sign = func(claims authkit.Claims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key"
		signed, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return signed
	}

	return server.URL, sign
}

func TestVerify(t *testing.T) {
	jwksURL, sign := newTestIssuer(t)

	v, err := authkit.NewVerifier(context.Background(), authkit.Config{
		JWKSURL:  jwksURL,
		Issuer:   "https://hydra.test/",
		Audience: "authz-api",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	validClaims := authkit.Claims{
		Roles: []string{"operator_admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://hydra.test/",
			Audience:  jwt.ClaimStrings{"authz-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tests := []struct {
		name    string
		claims  authkit.Claims
		wantErr error // nil means "expect success"
	}{
		{
			name:   "valid token",
			claims: validClaims,
		},
		{
			name: "expired token",
			claims: authkit.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://hydra.test/",
					Audience:  jwt.ClaimStrings{"authz-api"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				},
			},
			wantErr: authkit.ErrTokenExpired,
		},
		{
			name: "wrong issuer",
			claims: authkit.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://some-other-hydra/",
					Audience:  jwt.ClaimStrings{"authz-api"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			wantErr: authkit.ErrIssuerMismatch,
		},
		{
			name: "wrong audience",
			claims: authkit.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://hydra.test/",
					Audience:  jwt.ClaimStrings{"some-other-service"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			wantErr: authkit.ErrAudienceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := sign(tt.claims)

			claims, err := v.Verify(tokenString)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify() unexpected error: %v", err)
				}
				if !claims.HasRole("operator_admin") {
					t.Errorf("Verify() claims = %+v, want roles to include operator_admin", claims)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	jwksURL, _ := newTestIssuer(t)
	_, signWithOtherKey := newTestIssuer(t) // a second, unrelated key pair

	v, err := authkit.NewVerifier(context.Background(), authkit.Config{
		JWKSURL:  jwksURL,
		Issuer:   "https://hydra.test/",
		Audience: "authz-api",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tokenString := signWithOtherKey(authkit.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://hydra.test/",
			Audience:  jwt.ClaimStrings{"authz-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	_, err = v.Verify(tokenString)
	if !errors.Is(err, authkit.ErrInvalidToken) {
		t.Fatalf("Verify() error = %v, want %v", err, authkit.ErrInvalidToken)
	}
}

func TestVerify_AudienceCheckSkippedWhenNotConfigured(t *testing.T) {
	jwksURL, sign := newTestIssuer(t)

	v, err := authkit.NewVerifier(context.Background(), authkit.Config{
		JWKSURL: jwksURL,
		Issuer:  "https://hydra.test/",
		// Audience intentionally left empty — simulates a service that
		// hasn't adopted audience-scoped tokens yet.
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tokenString := sign(authkit.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://hydra.test/",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			// No Audience claim at all.
		},
	})

	if _, err := v.Verify(tokenString); err != nil {
		t.Fatalf("Verify() unexpected error when audience not configured: %v", err)
	}
}
