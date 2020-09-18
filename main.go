package main

import (
	"bytes"
	rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudentity/sample-go-mtls-oauth-client/pkg/acp"
	"io"
	"log"
	"net/http"
	"strconv"
)

const challengeLength = 43

var (
	acpOAuthConfig acp.Config

	clientID       = flag.String("clientId", "", "Application client ID")
	issuerURL      = flag.String("issuerUrl", "https://localhost:8443/default/default", "Issuer URL with provided tenant, and server ID")
	port           = flag.String("port", "18888", "Port where callback, and login endpoints will be exposed")
	certPath       = flag.String("cert", "certs/cert.pem", "A path to the file with a certificate")
	keyPath        = flag.String("key", "certs/cert-key.pem", "A path to the file with a private key")
	serverCertPath = flag.String("serverCert", "certs/server-cert.pem", "A path to the file with a server certificate")
	pkceEnabled    = flag.Bool("pkce", false, "Enables PKCE flow")
)

func main() {
	var (
		serverPort int
		acpClient  acp.Client
		err        error
		verifier   []byte
		challenge  string
	)

	flag.Parse()
	if serverPort, err = strconv.Atoi(*port); err != nil {
		log.Fatalln(err)
	}

	acpOAuthConfig = acp.Config{
		RedirectURL: fmt.Sprintf("http://localhost:%v/callback", serverPort),
		ClientID:    *clientID,
		Scopes:      []string{"openid"},
		AuthURL:     fmt.Sprintf("%v/oauth2/authorize", *issuerURL),
		TokenURL:    fmt.Sprintf("%v/oauth2/token", *issuerURL),
		PKCEEnabled: *pkceEnabled,
	}

	if acpClient, err = acp.NewClient(*serverCertPath, *certPath, *keyPath, acpOAuthConfig); err != nil {
		log.Fatalln(err)
	}

	if *pkceEnabled {
		if verifier, err = GenerateVerifier(); err != nil {
			log.Fatalln(err)
		}

		challenge = GenerateChallenge(encode(verifier))
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", callback(acpClient, encode(verifier)))
	handler.HandleFunc("/login", login(challenge))

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%v", serverPort),
		Handler: handler,
	}

	fmt.Printf("Login endpoint available at: http://%v/login\nCallback endpoint available at: %v\n\n", server.Addr, acpOAuthConfig.RedirectURL)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	} else {
		log.Println("server closed!")
	}
}

func login(challenge string) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, acpOAuthConfig.AuthorizeURL(challenge), http.StatusTemporaryRedirect)
	}
}

func callback(client acp.Client, verfier string) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		var (
			body       []byte
			err        error
			prettyJSON bytes.Buffer

			code = request.URL.Query().Get("code")
		)

		if body, err = client.Exchange(code, verfier); err != nil {
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

func GenerateChallenge(verifier string) string {
	hash := sha256.New()
	hash.Write([]byte(verifier))
	return encode(hash.Sum([]byte{}))
}

func GenerateVerifier() ([]byte, error) {
	verifier := make([]byte, challengeLength)
	if _, err := io.ReadFull(rand.Reader, verifier); err != nil {
		return []byte{}, err
	}

	return verifier, nil
}

func encode(msg []byte) string {
	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(msg)
}
