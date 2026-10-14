// Package middleware adapts authkit's Verifier and Can to net/http.
package middleware

import (
	"context"
	"net/http"
	"strings"

	authkit "github.com/Aman-6875/bus2-authkit"
)

type contextKey string

const claimsContextKey contextKey = "authkit.claims"

// RequireAuth verifies the request's bearer token and, on success, stores
// its claims in the request context for downstream handlers.
func RequireAuth(v *authkit.Verifier, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, authkit.ErrMissingToken.Error(), http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := v.Verify(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// ClaimsFromContext retrieves the claims RequireAuth stored, if any.
func ClaimsFromContext(ctx context.Context) (authkit.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(authkit.Claims)
	return claims, ok
}

// RequireRole wraps RequireAuth and additionally requires role.
func RequireRole(v *authkit.Verifier, role string, next http.HandlerFunc) http.HandlerFunc {
	return RequireAuth(v, func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		if !claims.HasRole(role) {
			http.Error(w, authkit.ErrForbidden.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// RequireCan wraps RequireAuth and additionally requires ability, per resolver.
func RequireCan(v *authkit.Verifier, ability string, resolver authkit.PermissionResolver, next http.HandlerFunc) http.HandlerFunc {
	return RequireAuth(v, func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		if !authkit.Can(claims, ability, resolver) {
			http.Error(w, authkit.ErrForbidden.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
