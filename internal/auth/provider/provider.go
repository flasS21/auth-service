package provider

import (
	"context"

	"auth-service/internal/auth"
)

// OAuthProvider defines the contract every external auth provider
// must implement. Implementations return identity facts only and
// must not perform user creation, linking, or session management.
type OAuthProvider interface {
	// Name returns the provider identifier (e.g. "google", "linkedin").
	Name() string

	// AuthCodeURL returns the OAuth authorization URL.
	// State and PKCE parameters are provided by the caller.
	AuthCodeURL(state string, codeChallenge string) string

	// ExchangeCode exchanges the authorization code for provider credentials
	// and returns a normalized identity. No auth decisions are made here.
	ExchangeCode(
		ctx context.Context,
		code string,
		codeVerifier string,
	) (*auth.Identity, error)
}
