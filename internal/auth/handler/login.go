package handler

import (
	"net/http"
	"time"

	"auth-service/internal/session"

	"github.com/gin-gonic/gin"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID, err := h.credentialService.Authenticate(
		c.Request.Context(),
		req.Email,
		req.Password,
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Create session
	sessionID, err := session.GenerateID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	if err := h.sessionStore.Create(
		c.Request.Context(),
		session.Session{
			SessionID: sessionID,
			UserID:    userID,
			ExpiresAt: expiresAt,
		},
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error"})
		return
	}

	session.SetCookie(
		c.Writer,
		sessionID,
		expiresAt,
		session.CookieOptions{
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		},
	)

	c.JSON(http.StatusOK, gin.H{"status": "logged_in"})
}
