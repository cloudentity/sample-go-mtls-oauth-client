package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
	"time"

	"github.com/caarlos0/env"
	acp "github.com/cloudentity/acp-client-go"
	"github.com/dgrijalva/jwt-go"
)

// in-memory token test store
var token acp.Token
var templ *template.Template
var usePyron bool
var xsslCertHash string
var resourceURL string
var injectCertMode bool

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
	ResourceURL       string   `env:"RESOURCE_URL"`
	XSSLCertHash      string   `env:"X_SSL_CERT_HASH"`
	InjectCertMode    bool     `env:"INJECT_CERT_MODE,required"`
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
	resourceURL = config.ResourceURL
	injectCertMode = config.InjectCertMode

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
	handler.HandleFunc("/balance", resource(client))
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
		parser := new(jwt.Parser)
		t, _, err := parser.ParseUnverified(token.AccessToken, jwt.MapClaims{})
		if err != nil {
			log.Fatal(err)
		}
		b, err := json.MarshalIndent(t.Claims, "", "\t")
		if err != nil {
			log.Fatal(err)
		}

		tokenResult := struct {
			Token           acp.Token
			UsePyron        bool
			FormattedClaims string
		}{
			Token:           token,
			UsePyron:        usePyron,
			FormattedClaims: string(b),
		}
		templ.ExecuteTemplate(w, "bootstrap", tokenResult)
	}
}

func resource(client acp.Client) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			res          *http.Response
			resBodyBytes []byte
			indentedJSON []byte
			err          error
		)
		if token.AccessToken == "" {
			templ.ExecuteTemplate(w, "error", token)
			return
		}

		if res, err = fetchResource(client); err != nil {
			log.Println(err)
			return
		}
		defer res.Body.Close()

		if resBodyBytes, err = io.ReadAll(res.Body); err != nil {
			log.Println(err)
			return
		}

		m := map[string]string{}
		if err = json.Unmarshal(resBodyBytes, &m); err != nil {
			log.Println(err)
			return
		}

		if indentedJSON, err = json.MarshalIndent(m, "", "\t"); err != nil {
			log.Println(err)
			return
		}

		resrourceRes := struct {
			Status  int
			Content string
		}{
			Status:  res.StatusCode,
			Content: string(indentedJSON),
		}

		templ.ExecuteTemplate(w, "resource", resrourceRes)
	}
}

func fetchResource(client acp.Client) (res *http.Response, err error) {
	var (
		httpClient *http.Client
		req        *http.Request
	)
	if httpClient, err = newHTTPClient(client.Config); err != nil {
		return nil, err
	}

	if req, err = newHTTPRequest(client.Config.ClientID); err != nil {
		return nil, err
	}

	return httpClient.Do(req)
}

func newHTTPClient(c acp.Config) (*http.Client, error) {
	var (
		pool  *x509.CertPool
		cert  tls.Certificate
		certs = []tls.Certificate{}
		data  []byte
		err   error
	)

	if c.CertFile != "" && c.KeyFile != "" {
		if cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
			return nil, fmt.Errorf("failed to read certificate and private key %v", err)
		}

		certs = append(certs, cert)
	}

	if pool, err = x509.SystemCertPool(); err != nil {
		return nil, fmt.Errorf("failed to read system root CAs %v", err)
	}

	if c.RootCA != "" {
		if data, err = os.ReadFile(c.RootCA); err != nil {
			return nil, fmt.Errorf("failed to read http client root ca: %w", err)
		}

		pool.AppendCertsFromPEM(data)
	}

	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			ResponseHeaderTimeout: c.Timeout,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				MinVersion:         tls.VersionTLS12,
				Certificates:       certs,
				InsecureSkipVerify: true,
			},
		},
	}, nil
}

func newHTTPRequest(clientID string) (req *http.Request, err error) {
	if req, err = http.NewRequest("GET", fmt.Sprintf("%s?client_id=%s", resourceURL, clientID), nil); err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{fmt.Sprintf("Bearer %s", token.AccessToken)},
	}

	if injectCertMode {
		req.Header.Add("x-ssl-cert-hash", xsslCertHash)
	}

	return req, err
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
