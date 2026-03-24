package cache

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrKeyNotFound = errors.New("cache: key not found")
	ErrConnection  = errors.New("cache: connection failed")
)

// RedisConfig holds the configuration for the Redis client.
// Designed for Upstash Redis (TLS-enabled, password-authenticated).
type RedisConfig struct {
	URI      string // Upstash Redis endpoint (e.g., "rediss://default:xxx@your-endpoint.upstash.io:6379")
	Password string // Upstash Redis password (used if URI does not embed credentials)
}

// RedisClient wraps the go-redis client with production-ready methods.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis connection configured for Upstash.
// It parses the URI, enables TLS (required by Upstash), verifies connectivity,
// and returns a ready-to-use client.
func NewRedisClient(cfg RedisConfig) *RedisClient {
	opt, err := redis.ParseURL(cfg.URI)
	if err != nil {
		log.Fatalf("redis: invalid URI: %v", err)
	}

	// Upstash requires TLS — ensure it's enabled even if the URI scheme is "redis://" instead of "rediss://".
	if opt.TLSConfig == nil {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	// Override password if provided separately (useful for secret injection via env).
	if cfg.Password != "" {
		opt.Password = cfg.Password
	}

	// Production pool settings.
	opt.PoolSize = 10
	opt.MinIdleConns = 3
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.WriteTimeout = 3 * time.Second
	opt.PoolTimeout = 4 * time.Second
	opt.MaxRetries = 3
	opt.MinRetryBackoff = 100 * time.Millisecond
	opt.MaxRetryBackoff = 500 * time.Millisecond

	client := redis.NewClient(opt)

	// Verify the connection at startup.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: ping failed: %v", err)
	}

	log.Println("Redis connected (Upstash)")
	return &RedisClient{client: client}
}

// ---------- Core Operations ----------

// Set stores a key-value pair with an expiration duration.
// A zero expiration means the key has no expiry.
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cache: marshal error for key %q: %w", key, err)
	}
	return r.client.Set(ctx, key, data, expiration).Err()
}

// Get retrieves a value by key and unmarshals it into dest.
// Returns ErrKeyNotFound if the key does not exist.
func (r *RedisClient) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("cache: get error for key %q: %w", key, err)
	}
	return json.Unmarshal(val, dest)
}

// Delete removes one or more keys.
func (r *RedisClient) Delete(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Exists checks whether a key exists. Returns true if it does.
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("cache: exists error for key %q: %w", key, err)
	}
	return n > 0, nil
}

// Expire updates the TTL on an existing key.
func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return r.client.Expire(ctx, key, expiration).Err()
}

// ---------- String Helpers (no JSON marshal) ----------

// SetRaw stores a raw string value (useful for tokens, OTPs, etc.).
func (r *RedisClient) SetRaw(ctx context.Context, key string, value string, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// GetRaw retrieves a raw string value.
// Returns ErrKeyNotFound if the key does not exist.
func (r *RedisClient) GetRaw(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrKeyNotFound
		}
		return "", fmt.Errorf("cache: get error for key %q: %w", key, err)
	}
	return val, nil
}

// ---------- Counter / Rate-Limiting ----------

// Increment atomically increments a key by 1 and returns the new value.
func (r *RedisClient) Increment(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// IncrementWithTTL atomically increments a key and sets a TTL if the key is new (count == 1).
// This is the building block for a sliding-window rate limiter.
func (r *RedisClient) IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("cache: incr error for key %q: %w", key, err)
	}
	// Only set expiry on the first increment so the window doesn't keep resetting.
	if count == 1 {
		if err := r.client.Expire(ctx, key, ttl).Err(); err != nil {
			return count, fmt.Errorf("cache: expire error for key %q: %w", key, err)
		}
	}
	return count, nil
}

// ---------- Hash Operations ----------

// HSet sets fields in a hash.
func (r *RedisClient) HSet(ctx context.Context, key string, values map[string]interface{}) error {
	return r.client.HSet(ctx, key, values).Err()
}

// HGetAll returns all fields and values of a hash.
func (r *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return r.client.HGetAll(ctx, key).Result()
}

// ---------- Set Operations (useful for blacklists / token revocation) ----------

// SAdd adds members to a set.
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return r.client.SAdd(ctx, key, members...).Err()
}

// SIsMember checks if a member exists in a set.
func (r *RedisClient) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	return r.client.SIsMember(ctx, key, member).Result()
}

// ---------- Refresh Token Session Store ----------
// Redis Key Design: refresh:{jti} → hashedToken
// Each refresh token is stored by its unique JTI with a TTL matching the token expiry.

const refreshKeyPrefix = "refresh:"

// StoreRefreshToken stores a hashed refresh token in Redis keyed by JTI.
// The expiry should match the refresh token's lifetime (e.g., 7 days).
func (r *RedisClient) StoreRefreshToken(ctx context.Context, jti string, hashedToken string, expiry time.Duration) error {
	key := refreshKeyPrefix + jti
	return r.client.Set(ctx, key, hashedToken, expiry).Err()
}

// GetRefreshToken retrieves the hashed refresh token by JTI.
// Returns ErrKeyNotFound if the token has expired or was revoked.
func (r *RedisClient) GetRefreshToken(ctx context.Context, jti string) (string, error) {
	key := refreshKeyPrefix + jti
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrKeyNotFound
		}
		return "", fmt.Errorf("cache: get refresh token error for jti %q: %w", jti, err)
	}
	return val, nil
}

// DeleteRefreshToken removes a refresh token from Redis (logout / revoke).
func (r *RedisClient) DeleteRefreshToken(ctx context.Context, jti string) error {
	key := refreshKeyPrefix + jti
	return r.client.Del(ctx, key).Err()
}

// DeleteAllUserRefreshTokens revokes all refresh tokens for a user by pattern.
// Key pattern: refresh:* — requires user-scoped prefix if multi-user cleanup is needed.
// For targeted revocation, prefer storing user→[]jti mapping and deleting individually.
func (r *RedisClient) DeleteRefreshTokensByPattern(ctx context.Context, pattern string) error {
	iter := r.client.Scan(ctx, 0, refreshKeyPrefix+pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := r.client.Del(ctx, iter.Val()).Err(); err != nil {
			return fmt.Errorf("cache: delete refresh token error for key %q: %w", iter.Val(), err)
		}
	}
	return iter.Err()
}

// ---------- Lifecycle ----------

// Ping checks the connection health.
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close gracefully shuts down the Redis connection pool.
func (r *RedisClient) Close() error {
	log.Println("Redis connection closed")
	return r.client.Close()
}

// Client returns the underlying go-redis client for advanced usage.
func (r *RedisClient) Client() *redis.Client {
	return r.client
}
