package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders sets HTTP response headers that harden the app against
// common web attacks (clickjacking, MIME sniffing, XSS, etc.).
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent the browser from MIME-sniffing the content type.
		c.Header("X-Content-Type-Options", "nosniff")

		// Block the page from being embedded in an iframe (clickjacking protection).
		c.Header("X-Frame-Options", "DENY")

		// Enable the browser's built-in XSS filter.
		c.Header("X-XSS-Protection", "1; mode=block")

		// Only send the origin as referrer, not the full URL (privacy + security).
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Restrict what browser features the app can access.
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Tell browsers to always use HTTPS for this domain (1 year).
		// Only takes effect when served over HTTPS.
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Prevent the browser from caching authenticated responses.
		c.Header("Cache-Control", "no-store")

		c.Next()
	}
}
