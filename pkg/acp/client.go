package acp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Client simple HTTP ACP client.
type Client struct {
	HttpClient *http.Client
	config     Config
}

// NewClient creates new instance of ACP client.
func NewClient(serverCertPath string, certPath string, keyPath string, cfg Config) (client Client, err error) {
	var cert tls.Certificate

	// It sets up the certificate HTTP client needs for TLS communication with a server.
	clientCACert, err := ioutil.ReadFile(serverCertPath)
	if err != nil {
		return Client{}, fmt.Errorf("could not open cert file %v: %w", certPath, err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	// It assigns a pool with certificates to the HTTP client.
	if cert, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return Client{}, fmt.Errorf("could not create acp client: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			// It assigns a pool with certificates to the HTTP client.
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      clientCertPool,
			},
		},
	}

	return Client{HttpClient: httpClient, config: cfg}, nil
}

func (c Client) Exchange(code string, verifier string) (body []byte, err error) {
	values := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {c.config.ClientID},
		"redirect_uri": {c.config.RedirectURL},
	}

	if c.config.PKCEEnabled {
		values.Add("code_verifier", verifier)
	}

	response, err := c.HttpClient.PostForm(c.config.TokenURL, values)
	if err != nil {
		return []byte{}, fmt.Errorf("error while obtaining token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return []byte{}, errors.New(fmt.Sprintf("ACP responded with status code: %v", response.Status))
	}

	if body, err = ioutil.ReadAll(response.Body); err != nil {
		return []byte{}, fmt.Errorf("error during decoding exchange body: %w", err)
	}

	return body, nil
}
