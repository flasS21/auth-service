package app

import (
	"context"

	"auth-service/internal/auth/handler"
	"auth-service/internal/auth/provider"
	"auth-service/internal/auth/provider/google"
	"auth-service/internal/auth/provider/keycloak"

	"auth-service/internal/auth/resolver"
	"auth-service/internal/config"
	"auth-service/internal/middleware"
	"auth-service/internal/session"

	"github.com/gin-gonic/gin"
)

var PROTECTED_DEMO = false

func setupHTTP(ctx context.Context, cfg config.Config) (*gin.Engine, func() error, error) {
	infra, err := setupInfra(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	// ----------------------------
	// Core dependencies
	// ----------------------------
	sessionStore := session.NewRedisStore(infra.Redis.Client)
	identityResolver := resolver.NewDBResolver(infra.DB)

	// ----------------------------
	// Google OAuth Provider
	// ----------------------------
	googleProvider, err := google.New(
		ctx,
		cfg.GoogleClientID,
		cfg.GoogleClientSecret,
		cfg.GoogleRedirectURL,
	)
	if err != nil {
		return nil, nil, err
	}

	// =============================
	// NEW: Keycloak OAuth Provider
	// =============================
	keycloakProvider, err := keycloak.New(
		ctx,
		cfg.KeycloakIssuer,
		cfg.KeycloakClientID,
		cfg.KeycloakRedirectURL,
		cfg.KeycloakPublicBaseURL,
	)
	if err != nil {
		return nil, nil, err
	}

	// ----------------------------
	// Provider registry
	// ----------------------------
	registry := provider.NewRegistry(
		googleProvider,
		keycloakProvider,
	)

	authHandler := handler.NewHandler(
		registry,
		sessionStore,
		identityResolver,
	)

	authMiddleware := middleware.NewAuthMiddleware(sessionStore)

	// ----------------------------
	// Router
	// ----------------------------
	router := gin.New()
	router.Use(gin.Recovery())

	// ----------------------------
	// OAuth routes
	// ----------------------------
	authHandler.RegisterRoutes(router)

	// ----------------------------
	// L E G A C Y - C L E A N - U P
	// ----------------------------

	// Email / Password auth routes (Phase-6)
	// ----------------------------
	// router.POST("/auth/login", authHandler.Login)
	// router.POST("/auth/register", authHandler.Register)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if PROTECTED_DEMO {

		// ----------------------------
		// Demo pages (PUBLIC)
		// ----------------------------
		router.GET("/", func(c *gin.Context) {
			c.File("internal/demo/index.html")
		})

		router.GET("/app", func(c *gin.Context) {
			c.File("internal/demo/app.html")
		})

		// ----------------------------
		// Demo dashboard (PROTECTED)
		// ----------------------------
		router.GET(
			"/dashboard",
			middleware.GinRequireAuth(authMiddleware),
			func(c *gin.Context) {
				c.File("internal/demo/dashboard.html")
			},
		)

		// ----------------------------
		// API (PROTECTED)
		// ----------------------------
		router.GET(
			"/api/me",
			middleware.GinRequireAuth(authMiddleware),
			func(c *gin.Context) {
				userID, ok := middleware.UserIDFromContext(c.Request.Context())
				if !ok {
					c.JSON(401, gin.H{"error": "unauthorized"})
					return
				}

				c.JSON(200, gin.H{
					"user_id": userID,
					"note":    "session-based auth via redis",
				})
			},
		)
	}

	// ----------------------------
	// Cleanup
	// ----------------------------
	return router, func() error {
		return infra.DB.Close()
	}, nil
}
