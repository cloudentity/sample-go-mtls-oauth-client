package main

import (
	"flag"
	"fmt"
	"github.com/cloudentity/sample-go-mtls-oauth-client/pkg/acp"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"strconv"
)

var (
	acpOAuthConfig *oauth2.Config

	clientID = flag.String("clientId", "", "Application client ID")
	acpURL   = flag.String("acpUrl", "https://localhost:8443/default/default/oauth2", "ACP URL with provided tenant, and server ID")
	port     = flag.String("port", "18888", "Port where callback, and login endpoints will be exposed")
	certPath = flag.String("cert", "cert", "A path to the file with a certificate")
	keyPath  = flag.String("key", "key", "A path to the file with a private key")
)

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

	acpOAuthConfig = &oauth2.Config{
		RedirectURL: fmt.Sprintf("http://localhost:%v/callback", serverPort),
		ClientID:    *clientID,
		Scopes:      []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%v/authorize", *acpURL),
			TokenURL:  fmt.Sprintf("%v/token", *acpURL),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	if acpClient, err = acp.NewClient(*certPath, *keyPath, *acpOAuthConfig); err != nil {
		log.Fatalln(err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/callback", callback(acpClient))
	handler.HandleFunc("/login", login)

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

func login(writer http.ResponseWriter, request *http.Request) {
	authURL := acpOAuthConfig.AuthCodeURL("12345")
	http.Redirect(writer, request, authURL, http.StatusTemporaryRedirect)
}

func callback(client acp.Client) func(http.ResponseWriter, *http.Request) {
	return func(_ http.ResponseWriter, request *http.Request) {
		var (
			body []byte
			err  error

			code = request.URL.Query().Get("code")
		)

		if body, err = client.Exchange(code); err != nil {
			log.Printf("%v\n", err)
			return
		}

		log.Println(string(body))
	}
}
