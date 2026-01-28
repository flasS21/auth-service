package handler

import (
	"net/http"
	"time"

	"auth-service/internal/auth/credentials"
	"auth-service/internal/session"

	"github.com/gin-gonic/gin"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID, err := h.credentialService.Register(
		c.Request.Context(),
		req.Email,
		req.Password,
	)

	if err != nil {
		switch err {
		case credentials.ErrAlreadyRegistered:
			c.JSON(http.StatusConflict, gin.H{"error": "account already exists"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
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

	c.JSON(http.StatusCreated, gin.H{"status": "registered"})
}
