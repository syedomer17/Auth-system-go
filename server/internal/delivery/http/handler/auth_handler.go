package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"auth-system/internal/config"
	"auth-system/internal/domain"
	"auth-system/internal/repository"
	"auth-system/internal/usecase"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles all authentication HTTP endpoints.
type AuthHandler struct {
	authUC *usecase.AuthUsecase
	cfg    *config.Config
}

func NewAuthHandler(authUC *usecase.AuthUsecase, cfg *config.Config) *AuthHandler {
	return &AuthHandler{authUC: authUC, cfg: cfg}
}

// Register godoc — POST /api/v1/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req domain.RegisterRequest
	if !bindJSON(c, &req) {
		return
	}
	req.Sanitize()

	user, tokens, err := h.authUC.Register(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}

	h.setTokenCookies(c, tokens)
	c.JSON(http.StatusCreated, gin.H{"user": user})
}

// Login godoc — POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req domain.LoginRequest
	if !bindJSON(c, &req) {
		return
	}
	req.Sanitize()

	user, tokens, err := h.authUC.Login(c.Request.Context(), req)
	if err != nil {
		// Generic message — don't reveal whether the email exists.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	h.setTokenCookies(c, tokens)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// Refresh godoc — POST /api/v1/auth/refresh
// Reads the refresh_token cookie, rotates it, and sets new cookies.
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing refresh token"})
		return
	}

	user, tokens, err := h.authUC.RefreshTokens(c.Request.Context(), refreshToken)
	if err != nil {
		h.clearTokenCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	h.setTokenCookies(c, tokens)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// Logout godoc — POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, _ := c.Cookie("refresh_token")
	if refreshToken != "" {
		// Best-effort revocation — don't fail the logout if Redis is down.
		_ = h.authUC.Logout(c.Request.Context(), refreshToken)
	}

	h.clearTokenCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// ---------- OAuth: Google ----------

// GoogleLogin godoc — GET /api/v1/auth/google
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	state := generateOAuthState()
	// Store state in a short-lived cookie for CSRF validation on callback.
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("oauth_state", state, 300, "/", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
	c.Redirect(http.StatusTemporaryRedirect, h.authUC.GoogleAuthURL(state))
}

// GoogleCallback godoc — GET /api/v1/auth/google/callback
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if !h.validateOAuthState(c) {
		return
	}

	user, tokens, err := h.authUC.GoogleCallback(c.Request.Context(), c.Query("code"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "google auth failed"})
		return
	}

	h.setTokenCookies(c, tokens)
	c.Redirect(http.StatusTemporaryRedirect, h.cfg.FrontendURL+"?user="+user.ID.Hex())
}

// ---------- OAuth: GitHub ----------

// GithubLogin godoc — GET /api/v1/auth/github
func (h *AuthHandler) GithubLogin(c *gin.Context) {
	state := generateOAuthState()
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("oauth_state", state, 300, "/", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
	c.Redirect(http.StatusTemporaryRedirect, h.authUC.GithubAuthURL(state))
}

// GithubCallback godoc — GET /api/v1/auth/github/callback
func (h *AuthHandler) GithubCallback(c *gin.Context) {
	if !h.validateOAuthState(c) {
		return
	}

	user, tokens, err := h.authUC.GithubCallback(c.Request.Context(), c.Query("code"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "github auth failed"})
		return
	}

	h.setTokenCookies(c, tokens)
	c.Redirect(http.StatusTemporaryRedirect, h.cfg.FrontendURL+"?user="+user.ID.Hex())
}

// ---------- Cookie Helpers ----------

// setTokenCookies sets HttpOnly secure cookies for both tokens.
// Access token: short-lived (15 min), sent on all API routes.
// Refresh token: long-lived (7 days), scoped to /api/v1/auth only.
func (h *AuthHandler) setTokenCookies(c *gin.Context, tokens *usecase.TokenPair) {
	c.SetSameSite(http.SameSiteLaxMode)

	// Access token — 15 minutes, HttpOnly.
	c.SetCookie("access_token", tokens.AccessToken, 15*60, "/", h.cfg.CookieDomain, h.cfg.CookieSecure, true)

	// Refresh token — 7 days, HttpOnly, scoped to auth endpoints only.
	c.SetCookie("refresh_token", tokens.RefreshToken, 7*24*60*60, "/api/v1/auth", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
}

// clearTokenCookies removes both token cookies.
func (h *AuthHandler) clearTokenCookies(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
	c.SetCookie("refresh_token", "", -1, "/api/v1/auth", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
}

// ---------- OAuth Helpers ----------

// validateOAuthState checks the state parameter against the stored cookie to prevent CSRF.
func (h *AuthHandler) validateOAuthState(c *gin.Context) bool {
	storedState, err := c.Cookie("oauth_state")
	if err != nil || storedState == "" || storedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oauth state"})
		return false
	}
	c.SetCookie("oauth_state", "", -1, "/", h.cfg.CookieDomain, h.cfg.CookieSecure, true)
	return true
}

// generateOAuthState creates a random hex string for OAuth CSRF protection.
func generateOAuthState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
