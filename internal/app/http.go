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

	// H E A L T H - C H E C K
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// P R O T E C T E D - R O U T E S
	protected := router.Group("/api")
	protected.Use(middleware.GinRequireAuth(authMiddleware))
	protected.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// -----------------------------------
	// Test Frontend (web-test)
	// -----------------------------------
	// router.Static("/web-test", "./web-test")

	// router.GET("/", func(c *gin.Context) {
	// 	c.File("./web-test/index.html")
	// })

	// router.GET("/dashboard.html", func(c *gin.Context) {
	// 	c.File("./web-test/dashboard.html")
	// })

	// ----------------------------
	// Cleanup
	// ----------------------------
	return router, func() error {
		return infra.DB.Close()
	}, nil

}
