package main

import (
	"bytes"
	rand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudentity/sample-go-mtls-oauth-client/pkg/acp"
	"github.com/gorilla/securecookie"
	"io"
	"log"
	"net/http"
	"strconv"
)

var (
	acpOAuthConfig acp.Config
	clientID       = flag.String("clientId", "", "Application client ID")
	issuerURL      = flag.String("issuerUrl", "https://localhost:8443/default/default", "Issuer URL with provided tenant, and server ID")
	port           = flag.String("port", "18888", "Port where callback, and login endpoints will be exposed")
	host           = flag.String("host", "localhost", "Host where your client applications is running")
	redirectHost   = flag.String("redirectHost", "localhost", "Host where the OAuth Server will redirect to")
	certPath       = flag.String("cert", "certs/cert.pem", "A path to the file with a certificate")
	keyPath        = flag.String("key", "certs/cert-key.pem", "A path to the file with a private key")
	serverCertPath = flag.String("serverCert", "certs/server-cert.pem", "A path to the file with a server certificate")
	pkceEnabled    = flag.Bool("pkce", false, "Enables PKCE flow")

	secureCookie = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
)

const challengeLength = 43

func main() {
	var (
		serverPort int
		acpClient  acp.Client
		err        error
	)

	flag.Parse()
	if serverPort, err = strconv.Atoi(*port); err != nil {
		log.Fatalln(err)
	}

	acpOAuthConfig = acp.Config{
		RedirectURL: fmt.Sprintf("http://%v:%v/callback", *redirectHost, serverPort),
		ClientID:    *clientID,
		Scopes:      []string{"openid"},
		AuthURL:     fmt.Sprintf("%v/oauth2/authorize", *issuerURL),
		TokenURL:    fmt.Sprintf("%v/oauth2/token", *issuerURL),
		PKCEEnabled: *pkceEnabled,
	}

	if acpClient, err = acp.NewClient(*serverCertPath, *certPath, *keyPath, acpOAuthConfig); err != nil {
		log.Fatalln(err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", callback(acpClient))
	handler.HandleFunc("/login", login)

	server := &http.Server{
		Addr:    fmt.Sprintf("%v:%v", *host, serverPort),
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

	fmt.Printf("Login endpoint available at: http://%v/login\nCallback endpoint available at: %v\n\n", server.Addr, acpOAuthConfig.RedirectURL)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	} else {
		log.Println("server closed!")
	}
}

func login(writer http.ResponseWriter, request *http.Request) {
	var challenge string

	//If PKCE is enabled, generate code verifier and challenge.
	if *pkceEnabled {
		var (
			encodedVerifier    string
			encodedCookieValue string
			err                error
		)

		verifier := make([]byte, challengeLength)
		if _, err = io.ReadFull(rand.Reader, verifier); err != nil {
			log.Printf("error while generating challenge, %v\n", err)
			return
		}

		encodedVerifier = base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(verifier)
		if encodedCookieValue, err = secureCookie.Encode("verifier", encodedVerifier); err != nil {
			log.Printf("error while encoding cookie, %v\n", err)
			return
		}

		// To preserve code verifier between authorization and callback, we want to store it in a secure cookie.
		cookie := http.Cookie{
			Name:     "verifier",
			Value:    encodedCookieValue,
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
		}
		http.SetCookie(writer, &cookie)

		hash := sha256.New()
		hash.Write([]byte(encodedVerifier))
		challenge = base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash.Sum([]byte{}))
	}

	http.Redirect(writer, request, acpOAuthConfig.AuthorizeURL(challenge), http.StatusTemporaryRedirect)
}

func callback(client acp.Client) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		var (
			body          []byte
			err           error
			verfier       *http.Cookie
			verifierValue string
			prettyJSON    bytes.Buffer

			// The request will contain this code to exchange it for an access token.
			code = request.URL.Query().Get("code")
		)

		if *pkceEnabled {
			if verfier, err = request.Cookie("verifier"); err != nil {
				log.Printf("%v\n", err)
				return
			}

			if err = secureCookie.Decode("verifier", verfier.Value, &verifierValue); err != nil {
				log.Printf("%v\n", err)
				return
			}
		}

		// Exchange code for an access token, include code verifier to validate it against challenge in ACP.
		if body, err = client.Exchange(code, verifierValue); err != nil {
			log.Printf("%v\n", err)
			return
		}

		if err = json.Indent(&prettyJSON, body, "", "\t"); err != nil {
			log.Printf("error while decoding successful body response: %v\n", err)
			return
		}

		if _, err = fmt.Fprint(writer, prettyJSON.String()); err != nil {
			log.Printf("error while writting successful body response: %v\n", err)
			return
		}
	}
}
