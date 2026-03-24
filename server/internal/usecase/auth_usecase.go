package usecase

import (
	"context"
	"fmt"
	"strconv"

	"auth-system/internal/domain"
	"auth-system/internal/infrastructure/oauth"
	"auth-system/internal/infrastructure/security"
	"auth-system/internal/repository"
)

// AuthUsecase contains all authentication business logic.
type AuthUsecase struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	googleOAuth *oauth.GoogleOAuth
	githubOAuth *oauth.GithubOAuth
	jwtSecret   string
}

func NewAuthUsecase(
	userRepo *repository.UserRepository,
	sessionRepo *repository.SessionRepository,
	googleOAuth *oauth.GoogleOAuth,
	githubOAuth *oauth.GithubOAuth,
	jwtSecret string,
) *AuthUsecase {
	return &AuthUsecase{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		googleOAuth: googleOAuth,
		githubOAuth: githubOAuth,
		jwtSecret:   jwtSecret,
	}
}

// TokenPair holds both tokens returned after authentication.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// Register creates a new local user and returns tokens.
func (u *AuthUsecase) Register(ctx context.Context, req domain.RegisterRequest) (*domain.User, *TokenPair, error) {
	// Hash the password before storing.
	hashed, err := security.HashPassword(req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: hash password: %w", err)
	}

	user := &domain.User{
		Email:    req.Email,
		Password: hashed,
		Name:     req.Name,
		Role:     domain.RoleUser,
		Provider: domain.ProviderLocal,
	}

	if err := u.userRepo.Create(ctx, user); err != nil {
		return nil, nil, err // ErrDuplicateEmail propagates to handler
	}

	// Generate token pair.
	tokens, err := u.generateTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	// Clear password before returning.
	user.Password = ""
	return user, tokens, nil
}

// Login authenticates a local user by email + password and returns tokens.
func (u *AuthUsecase) Login(ctx context.Context, req domain.LoginRequest) (*domain.User, *TokenPair, error) {
	user, err := u.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid email or password")
	}

	// Only local accounts can login with password.
	if user.Provider != domain.ProviderLocal {
		return nil, nil, fmt.Errorf("please login with %s", user.Provider)
	}

	if err := security.CheckPassword(req.Password, user.Password); err != nil {
		return nil, nil, fmt.Errorf("invalid email or password")
	}

	tokens, err := u.generateTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	user.Password = ""
	return user, tokens, nil
}

// RefreshTokens validates the old refresh token, rotates it, and returns new tokens.
// Rotation: old token is revoked, new one is issued — limits window if a token leaks.
func (u *AuthUsecase) RefreshTokens(ctx context.Context, oldRefreshToken string) (*domain.User, *TokenPair, error) {
	// Validate the old refresh token against Redis.
	claims, err := u.sessionRepo.ValidateSession(ctx, oldRefreshToken, u.jwtSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: invalid refresh token: %w", err)
	}

	// Revoke the old token (rotation).
	_ = u.sessionRepo.RevokeSession(ctx, oldRefreshToken, u.jwtSecret)

	// Look up the user to get current role (might have changed since token was issued).
	user, err := u.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: user not found: %w", err)
	}

	tokens, err := u.generateTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	user.Password = ""
	return user, tokens, nil
}

// Logout revokes the refresh token stored in Redis.
func (u *AuthUsecase) Logout(ctx context.Context, refreshToken string) error {
	return u.sessionRepo.RevokeSession(ctx, refreshToken, u.jwtSecret)
}

// ---------- OAuth ----------

// GoogleAuthURL returns the Google consent page URL.
func (u *AuthUsecase) GoogleAuthURL(state string) string {
	return u.googleOAuth.AuthURL(state)
}

// GoogleCallback handles the OAuth callback, finds or creates the user, and returns tokens.
func (u *AuthUsecase) GoogleCallback(ctx context.Context, code string) (*domain.User, *TokenPair, error) {
	gUser, err := u.googleOAuth.GetUser(ctx, code)
	if err != nil {
		return nil, nil, err
	}

	return u.findOrCreateOAuthUser(ctx, domain.ProviderGoogle, gUser.ID, gUser.Email, gUser.Name)
}

// GithubAuthURL returns the GitHub consent page URL.
func (u *AuthUsecase) GithubAuthURL(state string) string {
	return u.githubOAuth.AuthURL(state)
}

// GithubCallback handles the OAuth callback, finds or creates the user, and returns tokens.
func (u *AuthUsecase) GithubCallback(ctx context.Context, code string) (*domain.User, *TokenPair, error) {
	ghUser, err := u.githubOAuth.GetUser(ctx, code)
	if err != nil {
		return nil, nil, err
	}

	return u.findOrCreateOAuthUser(ctx, domain.ProviderGithub, strconv.Itoa(ghUser.ID), ghUser.Email, ghUser.Name)
}

// ---------- Helpers ----------

// findOrCreateOAuthUser looks up a user by provider+providerID.
// If not found, creates a new account. Then generates tokens.
func (u *AuthUsecase) findOrCreateOAuthUser(ctx context.Context, provider, providerID, email, name string) (*domain.User, *TokenPair, error) {
	// Try to find existing OAuth user.
	user, err := u.userRepo.FindByProvider(ctx, provider, providerID)
	if err != nil {
		// Not found — create a new user.
		user = &domain.User{
			Email:      email,
			Name:       name,
			Role:       domain.RoleUser,
			Provider:   provider,
			ProviderID: providerID,
		}
		if err := u.userRepo.Create(ctx, user); err != nil {
			return nil, nil, fmt.Errorf("auth: create oauth user: %w", err)
		}
	}

	tokens, err := u.generateTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	user.Password = ""
	return user, tokens, nil
}

// generateTokens creates an access token + refresh token (stored in Redis).
func (u *AuthUsecase) generateTokens(ctx context.Context, user *domain.User) (*TokenPair, error) {
	userID := user.ID.Hex()

	accessToken, err := security.GenerateAccessToken(userID, user.Role, u.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("auth: generate access token: %w", err)
	}

	refreshToken, err := u.sessionRepo.CreateSession(ctx, userID, u.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("auth: create session: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
