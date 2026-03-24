package middleware

import (
	"fmt"
	"net/http"
	"time"

	"auth-system/internal/infrastructure/cache"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig defines the window and max requests.
type RateLimitConfig struct {
	Window      time.Duration // e.g., 1 * time.Minute
	MaxRequests int64         // e.g., 60
}

// RateLimiter uses Redis to enforce per-IP rate limiting with a fixed window.
// Key pattern: ratelimit:{ip}:{window_epoch}
func RateLimiter(redisClient *cache.RedisClient, cfg RateLimitConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		// Use the window-aligned epoch as part of the key so the counter resets naturally.
		windowID := time.Now().Unix() / int64(cfg.Window.Seconds())
		key := fmt.Sprintf("ratelimit:%s:%d", ip, windowID)

		count, err := redisClient.IncrementWithTTL(c.Request.Context(), key, cfg.Window)
		if err != nil {
			// If Redis is down, let the request through — fail open to avoid a total outage.
			c.Next()
			return
		}

		// Set rate-limit headers so clients can self-throttle.
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.MaxRequests))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", max(0, cfg.MaxRequests-count)))

		if count > cfg.MaxRequests {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, try again later",
			})
			return
		}

		c.Next()
	}
}
