package acp

import (
	"bytes"
	"net/url"
	"strings"
)

type Config struct {
	// RedirectURL holds information where to redirect the user after successful authentication.
	RedirectURL string
	// ClientID is the ID of our client registered in ACP.
	ClientID string
	// Scopes must be at least a subset of scopes assigned to our application in ACP.
	Scopes []string
	// AuthURL is an URL where users can authenticate.
	AuthURL string
	// TokenURL holds information about the endpoint where we can exchange code for an access token.
	TokenURL string
	// PKCEEnabled is information whether PKCE is enabled or not.
	PKCEEnabled bool
}

// AuthorizeURL builds the URL where the client will redirect the user after accessing /login endpoint. Challenge is a
// string used only when PKCE is enabled.
func (c Config) AuthorizeURL(challenge string) string {
	var (
		buf bytes.Buffer

		queryParams = url.Values{
			"response_type": {"code"},
			"client_id":     {c.ClientID},
			"redirect_uri":  {c.RedirectURL},
			"scope":         {strings.Join(c.Scopes, " ")},
		}
	)

	// When PKCE is on, we need to add a code challenge to the authorization request.
	if c.PKCEEnabled {
		queryParams.Add("code_challenge", challenge)
		queryParams.Add("code_challenge_method", "S256")
	}

	buf.WriteString(c.AuthURL)
	if strings.Contains(c.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(queryParams.Encode())
	return buf.String()
}
