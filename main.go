package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"text/template"

	"github.com/caarlos0/env"
	acp "github.com/cloudentity/acp-client-go"
)

// in-memory token test store
var token acp.Token
var templ *template.Template
var usePyron bool
var xsslCertHash string

type Config struct {
	ClientID          string `env:"CLIENT_ID,required"`
	CertPath          string `env:"CERT_PATH,required"`
	KeyPath           string `env:"KEY_PATH,required"`
	RootCA            string `env:"ROOT_CA,required"`
	PORT              int    `env:"PORT,required"`
	RedirectHost      string `env:"REDIRECT_HOST,required"`
	WellKnown         string `env:"WELL_KNOWN_URL,required"`
	WellKnownURL      *url.URL
	IssuerURL         *url.URL `env:"ISSUER_URL"`
	AuthorizeEndpoint *url.URL `env:"AUTHORIZATION_ENDPOINT"`
	TokenEndpoint     *url.URL `env:"MTLS_ENDPOINT_ALIASES_TOKEN_ENDPOINT"`
	UsePyron          bool     `env:"USE_PYRON,required"`
	XSSLCertHash      string   `env:"X_SSL_CERT_HASH"`
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

	config.fetchEndpointURLs()
	usePyron = config.UsePyron
	xsslCertHash = config.XSSLCertHash

	return config, err
}

func layoutFiles() []string {
	files, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
	return files
}

func main() {
	var (
		config       Config
		authorizeURL string
		csrf         acp.CSRF
		client       acp.Client
		err          error
	)

	if config, err = LoadConfig(); err != nil {
		log.Fatalf("failed to load config %v", err)
	}

	if client, err = acp.New(config.NewClientConfig()); err != nil {
		log.Fatalf("failed to get oauth client %v", err)
	}

	if authorizeURL, csrf, err = client.AuthorizeURL(); err != nil {
		log.Fatal(err)
	}

	if templ, err = template.ParseFiles(layoutFiles()...); err != nil {
		log.Fatal(err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", callback(client, csrf))
	handler.HandleFunc("/home", home())
	handler.HandleFunc("/balance", balance(client))
	handler.HandleFunc("/login", login(authorizeURL))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%v", config.PORT),
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	fmt.Printf("Login endpoint available at: http://localhost:%v/login\nCallback endpoint available at: %v\n\n", config.PORT, client.Config.RedirectURL)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	} else {
		log.Println("server closed!")
	}
}

func login(authorizeURL string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
	}
}

func callback(client acp.Client, csrf acp.CSRF) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			code = r.URL.Query().Get("code")
			err  error
		)

		if token, err = client.Exchange(code, csrf.State, csrf); err != nil {
			log.Printf("%v\n", err)
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, "/home", http.StatusFound)
	}
}

func home() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if token.AccessToken == "" {
			templ.ExecuteTemplate(w, "error", token)
			return
		}
		tokenResult := struct {
			Token    acp.Token
			UsePyron bool
		}{
			Token:    token,
			UsePyron: usePyron,
		}
		templ.ExecuteTemplate(w, "bootstrap", tokenResult)
	}
}

func balance(client acp.Client) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			req *http.Request
			res *http.Response
			err error
		)
		if token.AccessToken == "" {
			templ.ExecuteTemplate(w, "error", token)
			return
		}
		c := http.Client{}
		if req, err = http.NewRequest("GET", fmt.Sprintf("http://pyron:8080/banking/balance?client_id=%s", client.Config.ClientID), nil); err != nil {
			log.Println(err)
			return
		}

		req.Header = http.Header{
			"Content-Type":    []string{"application/json"},
			"Authorization":   []string{fmt.Sprintf("Bearer %s", token.AccessToken)},
			"x-ssl-cert-hash": []string{xsslCertHash},
		}

		if res, err = c.Do(req); err != nil {
			log.Println(err)
			return
		}

		templ.ExecuteTemplate(w, "balance", res)
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
	json.NewDecoder(resp.Body).Decode(&we)

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
