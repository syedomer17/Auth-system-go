package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleUser holds the fields returned by Google's userinfo endpoint.
type GoogleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// GoogleOAuth manages the Google OAuth2 flow.
type GoogleOAuth struct {
	config *oauth2.Config
}

func NewGoogleOAuth(clientID, clientSecret, redirectURL string) *GoogleOAuth {
	return &GoogleOAuth{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
	}
}

// AuthURL returns the URL to redirect the user to for Google consent.
// The state parameter prevents CSRF — generate a random string per request.
func (g *GoogleOAuth) AuthURL(state string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// GetUser exchanges the authorization code for a token, then fetches user info.
func (g *GoogleOAuth) GetUser(ctx context.Context, code string) (*GoogleUser, error) {
	// Exchange code for OAuth token.
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google oauth: code exchange failed: %w", err)
	}

	// Fetch user info from Google.
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google oauth: failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("google oauth: failed to read response: %w", err)
	}

	var user GoogleUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("google oauth: failed to parse user info: %w", err)
	}

	return &user, nil
}
