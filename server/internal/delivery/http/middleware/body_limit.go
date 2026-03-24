package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit rejects requests with a Content-Length larger than maxBytes.
// This prevents clients from sending huge payloads that could eat memory.
// Default recommended: 1 MB for a JSON API.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}

		// Also wrap the body reader as a safeguard against chunked-encoding
		// requests that don't set Content-Length.
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
