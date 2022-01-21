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

const challengeLength = 43

var csrf acp.CSRF
var authorizeURL string

func main() {
	var (
		serverPort  int
		redirectURL *url.URL
		issuerURL   *url.URL
		clientID    string
		url         *url.URL
		client      acp.Client
		err         error
	)

	if clientID = getEnv("CLIENT_ID", ""); clientID == "" {
		log.Fatalln("clientID is required")
	}

	certPath := getEnv("CERT_PATH", "")
	keyPath := getEnv("KEY_PATH", "")
	rootCA := getEnv("ROOT_CA", "")
	host := getEnv("HOST", "")

	if serverPort, err = strconv.Atoi(getEnv("PORT", "")); err != nil {
		log.Fatalln(err)
	}

	if issuerURL, err = url.Parse(getEnv("ISSUER_URL", "")); err != nil {
		log.Fatal("cloud not parse issuer url")
	}

	if redirectURL, err = url.Parse(fmt.Sprintf("http://%v:%v/callback", getEnv("REDIRECT_HOST", ""), serverPort)); err != nil {
		log.Fatal(err)
	}

	cfg := acp.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		IssuerURL:   issuerURL,
		CertFile:    certPath,
		KeyFile:     keyPath,
		RootCA:      rootCA,
		Scopes:      []string{"openid"},
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
		Addr:    fmt.Sprintf("%v:%v", host, serverPort),
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

	fmt.Printf("Login endpoint available at: http://%v/login\nCallback endpoint available at: %v\n\n", server.Addr, cfg.RedirectURL)
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

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
