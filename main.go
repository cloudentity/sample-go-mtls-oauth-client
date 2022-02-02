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
	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var templ *template.Template
var appStorage AppStorage

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
	WellKnownURL       *url.URL
	IssuerURL          *url.URL
	AuthorizeEndpoint  *url.URL
	TokenEndpoint      *url.URL
	UsePyron           bool   `env:"USE_PYRON,required"`
	ResourceURL        string `env:"RESOURCE_URL"`
	XSSLCertHash       string `env:"X_SSL_CERT_HASH"`
	InjectCertMode     bool   `env:"INJECT_CERT_MODE,required"`
}

func (c Config) NewClientConfig() acp.Config {
	var (
		redirectURL *url.URL
		err         error
	)

	if redirectURL, err = url.Parse(fmt.Sprintf("http://%v:%v/callback", c.RedirectHost, c.PORT)); err != nil {
		log.Fatalf("failed to get callback url from host %v", err)
	}

	return acp.Config{
		ClientID:     c.ClientID,
		RedirectURL:  redirectURL,
		TokenURL:     c.TokenEndpoint,
		AuthorizeURL: c.AuthorizeEndpoint,
		IssuerURL:    c.IssuerURL,
		CertFile:     c.CertPath,
		KeyFile:      c.KeyPath,
		RootCA:       c.RootCA,
		Scopes:       []string{"openid"},
	}
}

func LoadConfig() (config Config, err error) {
	if err = env.Parse(&config); err != nil {
		return config, err
	}

	if config.WellKnownURL, err = url.Parse(config.WellKnown); err != nil {
		log.Fatalf("failed to parse wellknown as url %v", err)
	}

	return config, err
}

func loadTemplates() (*template.Template, error) {
	return template.ParseFiles(layoutFiles()...)
}

func layoutFiles() []string {
	files, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
	return files
}

type Server struct {
	Config       Config
	Client       acp.Client
	HttpClient   *http.Client
	SecureCookie *securecookie.SecureCookie
}

func NewServer() (Server, error) {
	var (
		client = Server{}
		err    error
	)

	if client.Config, err = LoadConfig(); err != nil {
		return client, errors.Wrapf(err, "failed to load config")
	}

	client.Config.fetchEndpointURLs()

	if client.Client, err = acp.New(client.Config.NewClientConfig()); err != nil {
		return client, errors.Wrapf(err, "failed to init acp client")
	}

	if client.HttpClient, err = newHTTPClient(client.Client, client.Config); err != nil {
		return client, errors.Wrapf(err, "failed to get http client")
	}

	client.SecureCookie = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))

	return client, nil
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
	var err error

	if templ, err = loadTemplates(); err != nil {
		return err
	}

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
	Issuer                string              `json:"issuer"`
	AuthorizationEndpoint string              `json:"authorization_endpoint"`
	MtlsEndpointAliases   MtlsEndpointAliases `json:"mtls_endpoint_aliases"`
}

type MtlsEndpointAliases struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func (c *Config) fetchEndpointURLs() {
	var (
		resp *http.Response
		we   WellKnownEndpoints
		err  error
	)

	if resp, err = http.Get(c.WellKnownURL.String()); err != nil {
		log.Fatalf("error retrieving .well-known %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal("failed to retreive .well-known contents. check that .well-known uri is correct")
	}

	if json.NewDecoder(resp.Body).Decode(&we); err != nil {
		log.Fatalf("failed to decode .well-known URI %v", err)
	}

	if c.IssuerURL, err = url.Parse(we.Issuer); err != nil {
		log.Fatal("could not get /issure endpoint from .well-known")
	}
	if c.AuthorizeEndpoint, err = url.Parse(we.AuthorizationEndpoint); err != nil {
		log.Fatal("could not get /authorize endpoint from .well-known")
	}
	if c.TokenEndpoint, err = url.Parse(we.MtlsEndpointAliases.TokenEndpoint); err != nil {
		log.Fatal("could not get /token endpoint from .well-known")
	}
}
