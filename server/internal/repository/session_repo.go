package repository

import (
	"context"
	"fmt"
	"time"

	"auth-system/internal/infrastructure/cache"
	"auth-system/internal/infrastructure/security"
)

const refreshTokenExpiry = 7 * 24 * time.Hour // matches JWT expiry in security.GenerateRefreshToken

// SessionRepository manages refresh token sessions backed by Redis.
type SessionRepository struct {
	cache *cache.RedisClient
}

func NewSessionRepository(cache *cache.RedisClient) *SessionRepository {
	return &SessionRepository{cache: cache}
}

// CreateSession generates a refresh token, hashes it with SHA-256, stores the hash
// in Redis keyed by "refresh:{jti}", and returns the raw signed token for the client cookie.
func (r *SessionRepository) CreateSession(ctx context.Context, userID string, jwtSecret string) (string, error) {
	// 1. Generate refresh token + JTI
	signedToken, jti, err := security.GenerateRefreshToken(userID, jwtSecret)
	if err != nil {
		return "", fmt.Errorf("session: generate refresh token: %w", err)
	}

	// 2. Hash the signed token before storing (so a Redis leak doesn't expose raw tokens)
	hashedToken := security.HashToken(signedToken)

	// 3. Store in Redis: refresh:{jti} → hashedToken
	if err := r.cache.StoreRefreshToken(ctx, jti, hashedToken, refreshTokenExpiry); err != nil {
		return "", fmt.Errorf("session: store refresh token: %w", err)
	}

	return signedToken, nil
}

// ValidateSession parses the refresh token, looks up the stored hash by JTI,
// and verifies the token matches. Returns the claims if valid.
func (r *SessionRepository) ValidateSession(ctx context.Context, rawToken string, jwtSecret string) (*security.RefreshClaims, error) {
	// 1. Parse and verify JWT signature + expiry
	claims, err := security.ParseRefreshToken(rawToken, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("session: invalid token: %w", err)
	}

	jti := claims.RegisteredClaims.ID
	if jti == "" {
		return nil, fmt.Errorf("session: token missing jti")
	}

	// 2. Look up hashed token in Redis
	storedHash, err := r.cache.GetRefreshToken(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("session: token not found or expired: %w", err)
	}

	// 3. Constant-time comparison of raw token against stored SHA-256 hash
	if err := security.CompareToken(rawToken, storedHash); err != nil {
		return nil, fmt.Errorf("session: token mismatch: %w", err)
	}

	return claims, nil
}

// RevokeSession deletes a single refresh token session by JTI (logout).
func (r *SessionRepository) RevokeSession(ctx context.Context, rawToken string, jwtSecret string) error {
	claims, err := security.ParseRefreshToken(rawToken, jwtSecret)
	if err != nil {
		return fmt.Errorf("session: invalid token: %w", err)
	}

	jti := claims.RegisteredClaims.ID
	if jti == "" {
		return fmt.Errorf("session: token missing jti")
	}

	return r.cache.DeleteRefreshToken(ctx, jti)
}
