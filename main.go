package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"text/template"

	"github.com/caarlos0/env"
	acp "github.com/cloudentity/acp-client-go"
	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type AppStorage struct {
	CSRF  acp.CSRF
	Token acp.Token
}

type Config struct {
	ClientID           string `env:"CLIENT_ID,required"`
	CertPath           string `env:"CERT_PATH,required"`
	KeyPath            string `env:"KEY_PATH,required"`
	RootCA             string `env:"ROOT_CA,required"`
	InsecureSkipVerify bool   `env:"INSECURE_SKIP_VERIFY"`
	PORT               int    `env:"PORT,required"`
	RedirectHost       string `env:"REDIRECT_HOST,required"`
	WellKnown          string `env:"WELL_KNOWN_URL,required"`
	Endpoints          WellKnownEndpoints
	UsePyron           bool   `env:"USE_PYRON,required"`
	ResourceURL        string `env:"RESOURCE_URL"`
	XSSLCertHash       string `env:"X_SSL_CERT_HASH"`
	InjectCertMode     bool   `env:"INJECT_CERT_MODE,required"`
}

func (c Config) NewClientConfig() (acp.Config, error) {
	var (
		redirectURL *url.URL
		err         error
	)

	if redirectURL, err = url.Parse(fmt.Sprintf("http://%v:%v/callback", c.RedirectHost, c.PORT)); err != nil {
		return acp.Config{}, errors.Wrap(err, "failed to get callback url from host")
	}

	return acp.Config{
		ClientID:     c.ClientID,
		RedirectURL:  redirectURL,
		TokenURL:     c.Endpoints.TokenEndpoint,
		AuthorizeURL: c.Endpoints.AuthorizationEndpoint,
		IssuerURL:    c.Endpoints.Issuer,
		CertFile:     c.CertPath,
		KeyFile:      c.KeyPath,
		RootCA:       c.RootCA,
		Scopes:       []string{"openid"},
	}, nil
}

func LoadConfig() (config Config, err error) {
	if err = env.Parse(&config); err != nil {
		return config, err
	}

	return config, err
}

func loadTemplates() (*template.Template, error) {
	files, err := filepath.Glob("templates/*.html")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get template file names")
	}
	return template.ParseFiles(files...)
}

type Server struct {
	Config       Config
	Client       acp.Client
	HttpClient   *http.Client
	SecureCookie *securecookie.SecureCookie
	Tmpl         *template.Template
	AppStorage   AppStorage
}

func NewServer() (Server, error) {
	var (
		config acp.Config
		server = Server{}
		err    error
	)

	if server.Tmpl, err = loadTemplates(); err != nil {
		return server, errors.Wrapf(err, "failed to load templates")
	}

	if server.Config, err = LoadConfig(); err != nil {
		return server, errors.Wrapf(err, "failed to load config")
	}

	if server.Config.Endpoints, err = fetchEndpointURLs(server.Config.WellKnown); err != nil {
		return server, errors.Wrap(err, "failed to fetch well-known endpoints")
	}

	if config, err = server.Config.NewClientConfig(); err != nil {
		return server, errors.Wrapf(err, "failed to get client configuration")
	}

	if server.Client, err = acp.New(config); err != nil {
		return server, errors.Wrapf(err, "failed to init acp client")
	}

	if server.HttpClient, err = newHTTPClient(server.Client, server.Config); err != nil {
		return server, errors.Wrapf(err, "failed to get http client")
	}

	server.SecureCookie = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))

	return server, nil
}

func newHTTPClient(client acp.Client, config Config) (*http.Client, error) {
	var (
		pool  *x509.CertPool
		cert  tls.Certificate
		certs = []tls.Certificate{}
		data  []byte
		err   error
	)

	if client.Config.CertFile != "" && client.Config.KeyFile != "" {
		if cert, err = tls.LoadX509KeyPair(client.Config.CertFile, client.Config.KeyFile); err != nil {
			return nil, fmt.Errorf("failed to read certificate and private key %v", err)
		}

		certs = append(certs, cert)
	}

	if pool, err = x509.SystemCertPool(); err != nil {
		return nil, fmt.Errorf("failed to read system root CAs %v", err)
	}

	if client.Config.RootCA != "" {
		if data, err = os.ReadFile(client.Config.RootCA); err != nil {
			return nil, fmt.Errorf("failed to read http client root ca: %w", err)
		}

		pool.AppendCertsFromPEM(data)
	}

	return &http.Client{
		Timeout: client.Config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				MinVersion:         tls.VersionTLS12,
				Certificates:       certs,
				InsecureSkipVerify: config.InsecureSkipVerify,
			},
		},
	}, nil
}

func (s *Server) Start() error {
	handler := http.NewServeMux()
	handler.HandleFunc("/login", s.Login)
	handler.HandleFunc("/callback", s.Callback)
	handler.HandleFunc("/home", s.Home)
	handler.HandleFunc("/resource", s.Resource)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%v", s.Config.PORT),
		Handler:      handler,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	fmt.Printf("Login endpoint available at: http://localhost:%v/login\nCallback endpoint available at: %v\n\n", s.Config.PORT, s.Client.Config.RedirectURL)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	} else {
		log.Println("server closed!")
	}

	return nil
}

func main() {
	var (
		server Server
		err    error
	)

	if server, err = NewServer(); err != nil {
		logrus.WithError(err).Fatalf("failed to init server")
	}

	if err = server.Start(); err != nil {
		logrus.WithError(err).Fatalf("failed to start server")
	}
}

type WellKnownEndpoints struct {
	Issuer                *url.URL `json:"issuer"`
	AuthorizationEndpoint *url.URL `json:"authorization_endpoint"`
	TokenEndpoint         *url.URL `json:"token_endpoint"`
}

func fetchEndpointURLs(wellKnownURL string) (WellKnownEndpoints, error) {
	var (
		endpoints WellKnownEndpoints
		resp      *http.Response
		we        models.WellKnown
		err       error
	)

	if resp, err = http.Get(wellKnownURL); err != nil {
		return endpoints, errors.Wrap(err, "error retrieving .well-known")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return endpoints, errors.Errorf("failed to retreive .well-known contents with status code %d", resp.StatusCode)
	}

	if err = json.NewDecoder(resp.Body).Decode(&we); err != nil {
		return endpoints, errors.Wrap(err, "failed to decode .well-known URI")
	}

	if endpoints.Issuer, err = url.Parse(we.Issuer); err != nil {
		return endpoints, errors.Wrap(err, "could not get /issure endpoint from .well-known")
	}

	if endpoints.AuthorizationEndpoint, err = url.Parse(we.AuthorizationEndpoint); err != nil {
		return endpoints, errors.Wrap(err, "could not get /authorize endpoint from .well-known")
	}

	if endpoints.TokenEndpoint, err = url.Parse(we.MtlsEndpointAliases.TokenEndpoint); err != nil {
		return endpoints, errors.Wrap(err, "could not get /token endpoint from .well-known")
	}

	return endpoints, nil
}
