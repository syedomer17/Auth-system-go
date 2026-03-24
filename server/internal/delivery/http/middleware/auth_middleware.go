package middleware

import (
	"net/http"
	"strings"

	"auth-system/internal/infrastructure/security"

	"github.com/gin-gonic/gin"
)

// Auth validates the access token from the cookie (or Authorization header as fallback).
// On success it sets "userID" and "role" in the gin context for downstream handlers.
func Auth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
			return
		}

		// Parse and validate the access token.
		claims, err := security.ParseAccessToken(token, jwtSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		// Store user info in context — available via c.GetString("userID") in handlers.
		c.Set("userID", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// extractToken reads the access token from the cookie first, then falls back to
// the Authorization: Bearer <token> header. Cookie-first is the default for browsers;
// header fallback supports API clients like Postman or mobile apps.
func extractToken(c *gin.Context) string {
	// 1. Try cookie.
	if token, err := c.Cookie("access_token"); err == nil && token != "" {
		return token
	}

	// 2. Fallback to Authorization header.
	header := c.GetHeader("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}

	return ""
}
