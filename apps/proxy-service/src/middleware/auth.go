package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================
// CONTEXT KEYS
// ============================================================

type ctxKey string

const (
	CtxOrgID  ctxKey = "orgId"
	CtxAPIKey ctxKey = "apiKey"
	CtxUserID ctxKey = "userId"
	CtxEmail  ctxKey = "userEmail"
	CtxRole   ctxKey = "userRole"
)

// OrgLookupFunc queries the database/cache for an org by API key.
// The proxy main.go wires this to the actual store.
type OrgLookupFunc func(ctx context.Context, apiKey string) (orgID string, err error)

// ============================================================
// API KEY AUTH (for browser extension → proxy)
// ============================================================

func APIKeyAuth(lookupOrg OrgLookupFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract API key from Authorization header or X-API-Key
			apiKey := ""
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
			if apiKey == "" {
				apiKey = r.Header.Get("X-API-Key")
			}

			if apiKey == "" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing API key"}}`, http.StatusUnauthorized)
				return
			}

			orgID, err := lookupOrg(r.Context(), apiKey)
			if err != nil || orgID == "" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid API key"}}`, http.StatusUnauthorized)
				return
			}

			// Also check X-Org-Id header matches (defense in depth)
			headerOrgID := r.Header.Get("X-Org-Id")
			if headerOrgID != "" && headerOrgID != orgID {
				http.Error(w, `{"error":{"code":"FORBIDDEN","message":"Org ID mismatch"}}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), CtxOrgID, orgID)
			ctx = context.WithValue(ctx, CtxAPIKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================
// JWT AUTH (for dashboard → proxy API)
// ============================================================

type JWTClaims struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	OrgID  string `json:"orgId"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing token"}}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims := &JWTClaims{}

			token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(secret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token"}}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), CtxOrgID, claims.OrgID)
			ctx = context.WithValue(ctx, CtxUserID, claims.UserID)
			ctx = context.WithValue(ctx, CtxEmail, claims.Email)
			ctx = context.WithValue(ctx, CtxRole, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GenerateJWT creates a JWT for dashboard login
func GenerateJWT(secret, userID, email, orgID, role string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		OrgID:  orgID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "shadow-ai-sentinel",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ============================================================
// HELPER: Extract values from context
// ============================================================

func GetOrgID(ctx context.Context) string {
	if v, ok := ctx.Value(CtxOrgID).(string); ok {
		return v
	}
	return ""
}

func GetUserID(ctx context.Context) string {
	if v, ok := ctx.Value(CtxUserID).(string); ok {
		return v
	}
	return ""
}

func GetEmail(ctx context.Context) string {
	if v, ok := ctx.Value(CtxEmail).(string); ok {
		return v
	}
	return ""
}

func GetRole(ctx context.Context) string {
	if v, ok := ctx.Value(CtxRole).(string); ok {
		return v
	}
	return ""
}
