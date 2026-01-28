// package handler

// import (
// 	"net/http"
// 	"time"

// 	"auth-service/internal/auth/provider"
// 	"auth-service/internal/auth/resolver"
// 	"auth-service/internal/session"

// 	"github.com/gin-gonic/gin"
// )

// type Handler struct {
// 	providers    *provider.Registry
// 	sessionStore session.Store
// 	resolver     resolver.Resolver
// }

// func NewHandler(
// 	registry *provider.Registry,
// 	sessionStore session.Store,
// 	resolver resolver.Resolver,
// ) *Handler {
// 	return &Handler{
// 		providers:    registry,
// 		sessionStore: sessionStore,
// 		resolver:     resolver,
// 	}
// }

// func (h *Handler) RegisterRoutes(r *gin.Engine) {
// 	r.GET("/oauth/login/:provider", h.login)
// 	r.GET("/oauth/callback/:provider", h.callback)
// }

// func (h *Handler) login(c *gin.Context) {
// 	providerName := c.Param("provider")

// 	p, err := h.providers.Get(providerName)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "unknown oauth provider",
// 		})
// 		return
// 	}

// 	state := generateState(c)
// 	_, codeChallenge := generatePKCE(c)

// 	authURL := p.AuthCodeURL(state, codeChallenge)
// 	c.Redirect(http.StatusFound, authURL)
// }

// func (h *Handler) callback(c *gin.Context) {
// 	providerName := c.Param("provider")

// 	p, err := h.providers.Get(providerName)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "unknown oauth provider",
// 		})
// 		return
// 	}

// 	if !validateState(c) {
// 		c.JSON(http.StatusUnauthorized, gin.H{
// 			"error": "invalid state",
// 		})
// 		return
// 	}

// 	code := c.Query("code")
// 	if code == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "missing authorization code",
// 		})
// 		return
// 	}

// 	codeVerifier := getPKCEVerifier(c)
// 	if codeVerifier == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{
// 			"error": "missing pkce verifier",
// 		})
// 		return
// 	}

// 	identity, err := p.ExchangeCode(
// 		c.Request.Context(),
// 		code,
// 		codeVerifier,
// 	)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{
// 			"error": "authentication failed",
// 		})
// 		return
// 	}

// 	// NOTE: identity will be resolved to a user via Keystone identity resolver
// 	_ = identity

// 	userID, err := h.resolver.Resolve(c.Request.Context(), identity)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"error": "failed to resolve user",
// 		})
// 		return
// 	}

// 	// Create session
// 	sessionID, err := session.GenerateID()
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"error": "failed to create session",
// 		})
// 		return
// 	}

// 	expiresAt := time.Now().Add(24 * time.Hour)

// 	sess := session.Session{
// 		SessionID: sessionID,
// 		UserID:    userID,
// 		ExpiresAt: expiresAt,
// 	}

// 	if err := h.sessionStore.Create(c.Request.Context(), sess); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"error": "failed to persist session",
// 		})
// 		return
// 	}

// 	// Issue session cookie
// 	session.SetCookie(c.Writer, sessionID, expiresAt, session.CookieOptions{
// 		Secure:   true, // make configurable later
// 		SameSite: http.SameSiteLaxMode,
// 	})

// 	// Redirect user (frontend entry point)
// 	// c.Redirect(http.StatusFound, "/app")
// 	c.JSON(http.StatusOK, gin.H{
// 		"status": "authenticated",
// 	})

// }

package handler

import (
	"net/http"
	"time"

	"auth-service/internal/auth/credentials"
	"auth-service/internal/auth/provider"
	"auth-service/internal/auth/resolver"
	"auth-service/internal/session"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	providers         *provider.Registry
	sessionStore      session.Store
	resolver          resolver.Resolver
	credentialService *credentials.Service
}

func NewHandler(
	registry *provider.Registry,
	sessionStore session.Store,
	resolver resolver.Resolver,
	credentialService *credentials.Service,
) *Handler {
	return &Handler{
		providers:         registry,
		sessionStore:      sessionStore,
		resolver:          resolver,
		credentialService: credentialService,
	}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	r.GET("/oauth/login/:provider", h.login)
	r.GET("/oauth/callback/:provider", h.callback)
}

func (h *Handler) login(c *gin.Context) {
	providerName := c.Param("provider")

	p, err := h.providers.Get(providerName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unknown oauth provider",
		})
		return
	}

	state := generateState(c)
	_, codeChallenge := generatePKCE(c)

	authURL := p.AuthCodeURL(state, codeChallenge)
	c.Redirect(http.StatusFound, authURL)
}

func (h *Handler) callback(c *gin.Context) {
	providerName := c.Param("provider")

	p, err := h.providers.Get(providerName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unknown oauth provider",
		})
		return
	}

	if !validateState(c) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid state",
		})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "missing authorization code",
		})
		return
	}

	codeVerifier := getPKCEVerifier(c)
	if codeVerifier == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "missing pkce verifier",
		})
		return
	}

	identity, err := p.ExchangeCode(
		c.Request.Context(),
		code,
		codeVerifier,
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication failed",
		})
		return
	}

	userID, err := h.resolver.Resolve(c.Request.Context(), identity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to resolve user",
		})
		return
	}

	sessionID, err := session.GenerateID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create session",
		})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	sess := session.Session{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}

	if err := h.sessionStore.Create(c.Request.Context(), sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to persist session",
		})
		return
	}

	session.SetCookie(c.Writer, sessionID, expiresAt, session.CookieOptions{
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	c.JSON(http.StatusOK, gin.H{
		"status": "authenticated",
	})
}
