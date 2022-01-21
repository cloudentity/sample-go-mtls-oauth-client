package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	acp "github.com/cloudentity/acp-client-go"
)

// var (
// 	acpOAuthConfig acp.Config
// 	clientID       = flag.String("clientId", "", "Application client ID")
// 	issuerURL      = flag.String("issuerUrl", "https://localhost:8443/default/default", "Issuer URL with provided tenant, and server ID")
// 	port           = flag.String("port", "18888", "Port where callback, and login endpoints will be exposed")
// 	host           = flag.String("host", "localhost", "Host where your client applications is running")
// 	redirectHost   = flag.String("redirectHost", "localhost", "Host where the OAuth Server will redirect to")
// 	certPath       = flag.String("cert", "certs/acp_cert.pem", "A path to the file with a certificate")
// 	keyPath        = flag.String("key", "certs/acp_key.pem", "A path to the file with a private key")
// 	rootCA         = flag.String("serverCert", "certs/ca.pem", "A path to the file with rootCA")
// 	pkceEnabled    = flag.Bool("pkce", false, "Enables PKCE flow")

// 	secureCookie = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
// )

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

const challengeLength = 43

var csrf acp.CSRF
var authorizeURL string

func main() {
	var (
		serverPort        int
		redirectURL       *url.URL
		issuerURL         *url.URL
		authorizeEndpoint *url.URL
		tokenEndpoint     *url.URL
		clientID          string
		url               *url.URL
		client            acp.Client
		err               error
	)

	if clientID = getEnv("CLIENT_ID", ""); clientID == "" {
		log.Fatalln("a client ID is required")
	}

	// c := http.Get(issuerURL)

	certPath := getEnv("CERT_PATH", "certs/acp_cert.pem")
	keyPath := getEnv("KEY_PATH", "certs/acp_cert.pem")
	rootCA := getEnv("ROOT_CA", "certs/acp_cert.pem")
	// host := getEnv("HOST", "localhost")

	if serverPort, err = strconv.Atoi(getEnv("PORT", "18888")); err != nil {
		log.Fatalln(err)
	}

	if issuerURL, err = url.Parse(getEnv("ISSUER_URL", "")); err != nil {
		log.Fatal("cloud not parse issuer url")
	}

	if redirectURL, err = url.Parse(fmt.Sprintf("http://%v:%v/callback", getEnv("REDIRECT_HOST", "localhost"), serverPort)); err != nil {
		log.Fatal(err)
	}

	if authorizeEndpoint, err = url.Parse(getEnv("AUTHORIZATION_ENDPOINT", "")); err != nil {
		log.Fatal("cloud not parse issuer url")
	}

	if tokenEndpoint, err = url.Parse(getEnv("MTLS_ENDPOINT_ALIASES_TOKEN_ENDPOINT", "")); err != nil {
		log.Fatal("cloud not parse issuer url")
	}

	cfg := acp.Config{
		ClientID:     clientID,
		RedirectURL:  redirectURL,
		TokenURL:     tokenEndpoint,
		AuthorizeURL: authorizeEndpoint,
		IssuerURL:    issuerURL,
		CertFile:     certPath,
		KeyFile:      keyPath,
		RootCA:       rootCA,
		Scopes:       []string{"openid"},
	}

	if client, err = acp.New(cfg); err != nil {
		log.Fatalln(err)
	}

	if authorizeURL, csrf, err = client.AuthorizeURL(); err != nil {
		log.Println(err)
		return
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", callback(client))
	handler.HandleFunc("/login", login(client))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%v", serverPort),
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

	fmt.Printf("Login endpoint available at: http://localhost:%v/login\nCallback endpoint available at: %v\n\n", serverPort, cfg.RedirectURL)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	} else {
		log.Println("server closed!")
	}
}

func login(client acp.Client) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
	}

}

func callback(client acp.Client) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			token acp.Token
			// The request will contain this code to exchange it for an access token.
			code = r.URL.Query().Get("code")
			err  error
		)

		// Exchange code for an access token.
		if token, err = client.Exchange(code, csrf.State, csrf); err != nil {
			log.Printf("%v\n", err)
			w.Write([]byte(err.Error()))
			return
		}

		if err = json.NewEncoder(w).Encode(&token); err != nil {
			log.Println(err)
		}
	}
}
