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
}

func (c Config) AuthorizeURL() string {
	var (
		buf bytes.Buffer

		queryParams = url.Values{
			"response_type": {"code"},
			"client_id":     {c.ClientID},
			"redirect_uri":  {c.RedirectURL},
			"scope":         {strings.Join(c.Scopes, " ")},
		}
	)

	buf.WriteString(c.AuthURL)
	if strings.Contains(c.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(queryParams.Encode())
	return buf.String()
}
