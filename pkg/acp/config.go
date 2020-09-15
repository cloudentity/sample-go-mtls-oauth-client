package acp

import (
	"bytes"
	"net/url"
	"strings"
)

type Config struct {
	RedirectURL string
	ClientID    string
	Scopes      []string
	AuthURL     string
	TokenURL    string
	PKCEEnabled bool
}

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
