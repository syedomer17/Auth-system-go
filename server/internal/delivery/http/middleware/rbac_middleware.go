package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole checks that the authenticated user has one of the allowed roles.
// Must be used AFTER the Auth middleware (which sets "role" in the context).
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	// Build a set for O(1) lookup.
	roleSet := make(map[string]struct{}, len(allowedRoles))
	for _, r := range allowedRoles {
		roleSet[r] = struct{}{}
	}

	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing role"})
			return
		}

		if _, ok := roleSet[role.(string)]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		c.Next()
	}
}
