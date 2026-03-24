package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
)

// RequestID generates a unique ID for every request and sets it in the
// response header and gin context. Useful for tracing logs across services.
// Downstream code can read it with c.GetString("requestID").
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if the caller already sent one (e.g., API gateway, load balancer).
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = generateID()
		}

		c.Set("requestID", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// generateID creates a 16-byte random hex string (32 chars).
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
