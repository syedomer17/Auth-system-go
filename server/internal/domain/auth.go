package domain

import "strings"

// ---------- Request DTOs ----------
// Gin's binding tags handle validation. Call Sanitize() after binding
// to normalize inputs before they hit the business logic layer.

// RegisterRequest is the body for POST /auth/register.
type RegisterRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=72"` // max 72 for bcrypt limit
	Name     string `json:"name"     binding:"required,min=2,max=100"`
}

// Sanitize normalizes user input — lowercase email, trim whitespace.
func (r *RegisterRequest) Sanitize() {
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	r.Name = strings.TrimSpace(r.Name)
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Sanitize normalizes user input.
func (r *LoginRequest) Sanitize() {
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
}

// ---------- Response DTOs ----------

// AuthResponse is returned after login/register — user data only.
// Tokens go in HttpOnly cookies, never in the response body.
type AuthResponse struct {
	User User `json:"user"`
}
