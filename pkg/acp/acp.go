package acp

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strings"
)

type Client struct {
	HttpClient *http.Client
	config     oauth2.Config
}

func NewClient(certPath string, keyPath string, cfg oauth2.Config) (client Client, err error) {
	var cert tls.Certificate

	if cert, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return Client{}, fmt.Errorf("could not create acp client: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	return Client{HttpClient: httpClient, config: cfg}, nil
}

func (c Client) Exchange(code string) (body []byte, err error) {
	queryParams := fmt.Sprintf("grant_type=authorization_code&code=%v&client_id=%v&redirect_uri=%v", code, c.config.ClientID, c.config.RedirectURL)

	response, err := c.HttpClient.Post(c.config.Endpoint.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(queryParams))
	if err != nil {
		return []byte{}, fmt.Errorf("error while obtaining token: %w", err)
	}

	if body, err = ioutil.ReadAll(response.Body); err != nil {
		return []byte{}, fmt.Errorf("error during decoding exchange body: %w", err)
	}

	return body, nil
}
