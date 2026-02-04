package middleware

import (
	"context"
	"net/http"
	"time"

	"auth-service/internal/session"
)

// unexported, collision-proof context key
type userIDContextKeyType struct{}

var userIDKey = userIDContextKeyType{}

const (
	IdleTimeout = 30 * time.Minute
)

// UserIDFromContext extracts the authenticated user ID from context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok
}

type AuthMiddleware struct {
	Store session.Store
}

func NewAuthMiddleware(store session.Store) *AuthMiddleware {
	return &AuthMiddleware{Store: store}
}

func (a *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Read session cookie
		cookie, err := r.Cookie(session.CookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		sessionID := cookie.Value

		// 2. Load session
		sess, err := a.Store.Get(r.Context(), sessionID)
		if err != nil || sess == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// 3. Keystone fix: enforce session expiry
		if time.Now().After(sess.ExpiresAt) {
			_ = a.Store.Delete(r.Context(), sessionID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// 3.5 Sliding window: extend session expiry on activity
		newExpiry := time.Now().Add(IdleTimeout)

		// Extend only if later than current expiry
		if newExpiry.After(sess.ExpiresAt) {
			sess.ExpiresAt = newExpiry
			_ = a.Store.Update(r.Context(), *sess)
		}

		// 4. Attach user_id to context
		ctx := context.WithValue(r.Context(), userIDKey, sess.UserID)

		// 5. Continue request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
