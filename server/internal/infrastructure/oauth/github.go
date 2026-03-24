package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GithubUser holds the fields returned by GitHub's user API.
type GithubUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"` // GitHub username — used as fallback for Name
}

// GithubEmail is one entry from GitHub's /user/emails endpoint.
type GithubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GithubOAuth manages the GitHub OAuth2 flow.
type GithubOAuth struct {
	config *oauth2.Config
}

func NewGithubOAuth(clientID, clientSecret, redirectURL string) *GithubOAuth {
	return &GithubOAuth{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		},
	}
}

// AuthURL returns the URL to redirect the user to for GitHub consent.
func (g *GithubOAuth) AuthURL(state string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// GetUser exchanges the authorization code for a token, then fetches user info.
func (g *GithubOAuth) GetUser(ctx context.Context, code string) (*GithubUser, error) {
	// Exchange code for OAuth token.
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github oauth: code exchange failed: %w", err)
	}

	// Fetch user profile.
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github oauth: failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github oauth: failed to read response: %w", err)
	}

	var user GithubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("github oauth: failed to parse user info: %w", err)
	}

	// Use login (username) as name fallback.
	if user.Name == "" {
		user.Name = user.Login
	}

	// GitHub may not return email on the /user endpoint if it's private.
	// In that case, fetch from the /user/emails endpoint.
	if user.Email == "" {
		email, err := fetchPrimaryEmail(client, ctx)
		if err != nil {
			return nil, err
		}
		user.Email = email
	}

	return &user, nil
}

// fetchPrimaryEmail gets the user's primary verified email from /user/emails.
func fetchPrimaryEmail(client *http.Client, ctx context.Context) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", fmt.Errorf("github oauth: failed to get emails: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("github oauth: failed to read emails response: %w", err)
	}

	var emails []GithubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("github oauth: failed to parse emails: %w", err)
	}

	// Pick the primary verified email.
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	return "", fmt.Errorf("github oauth: no verified primary email found")
}
