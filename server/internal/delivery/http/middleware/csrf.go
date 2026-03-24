package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"auth-system/internal/config"

	"github.com/gin-gonic/gin"
)

// CSRF implements the double-submit cookie pattern:
//
//  1. If the client has no csrf_token cookie, the middleware generates one and
//     sets it as a non-HttpOnly cookie (so JS can read it).
//  2. On state-changing methods (POST, PATCH, PUT, DELETE), the middleware
//     requires the X-CSRF-Token header to match the csrf_token cookie.
//
// Why this works: an attacker on a different origin can trigger the browser to
// send the cookie, but can't *read* it (same-origin policy), so they can't
// set the matching header.
func CSRF(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// --- Ensure the CSRF cookie exists ---
		token, err := c.Cookie("csrf_token")
		if err != nil || token == "" {
			token = generateCSRFToken()
			// Non-HttpOnly so the frontend JS can read it and attach it as a header.
			// SameSite=Strict prevents the cookie from being sent on cross-origin requests.
			c.SetSameSite(http.SameSiteStrictMode)
			c.SetCookie("csrf_token", token, 60*60*24, "/", cfg.CookieDomain, cfg.CookieSecure, false)
		}

		// --- Safe methods don't need CSRF validation ---
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// --- Validate: header must match cookie ---
		headerToken := c.GetHeader("X-CSRF-Token")
		if headerToken == "" || headerToken != token {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "CSRF token missing or invalid",
			})
			return
		}

		c.Next()
	}
}

// generateCSRFToken creates a cryptographically random 32-byte hex string.
func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
