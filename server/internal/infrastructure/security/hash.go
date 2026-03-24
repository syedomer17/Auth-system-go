package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ---------- Password Hashing (bcrypt) ----------

// HashPassword hashes a plaintext password using bcrypt with cost 12.
// Use this ONLY for passwords — bcrypt truncates input at 72 bytes.
func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ---------- Token Hashing (SHA-256) ----------
// JWT tokens are 300+ bytes — bcrypt silently truncates at 72 bytes,
// meaning different tokens could produce the same hash. SHA-256 has no
// length limit and is safe here because JWTs are high-entropy random strings.

// HashToken creates a SHA-256 hex digest of a token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CompareToken does a constant-time comparison of a token against its SHA-256 hash.
func CompareToken(token, hash string) error {
	computed := HashToken(token)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) != 1 {
		return errors.New("token mismatch")
	}
	return nil
}
