package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt"
)

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var (
		authorizeURL       string
		encodedCookieValue string
		storage            AppStorage
		err                error
	)

	if authorizeURL, storage.CSRF, err = s.Client.AuthorizeURL(); err != nil {
		renderError(w, ErrorDetails{http.StatusInternalServerError, fmt.Sprintf("failed to get authorization url: %+v", err)})
		return
	}

	if encodedCookieValue, err = s.SecureCookie.Encode("app", storage); err != nil {
		renderError(w, ErrorDetails{http.StatusInternalServerError, fmt.Sprintf("error while encoding cookie: %+v", err)})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "app",
		Value: encodedCookieValue,
		Path:  "/",
	})

	http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
}

func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
	var (
		code   = r.URL.Query().Get("code")
		cookie *http.Cookie
		errVal = r.URL.Query().Get("error")
		err    error
	)

	if errVal != "" {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("acp returned an error: %s: %s", errVal, r.URL.Query().Get("error_description"))})
		return
	}

	if cookie, err = r.Cookie("app"); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("failed to get app cookie: %+v", err)})
		return
	}

	if err = s.SecureCookie.Decode("app", cookie.Value, &appStorage); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("failed to decode app storage: %+v", err)})
		return
	}

	if appStorage.Token, err = s.Client.Exchange(code, r.URL.Query().Get("state"), appStorage.CSRF); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("failed to get token: %+v", err)})
		return
	}

	http.Redirect(w, r, "/home", http.StatusFound)

}

func (s *Server) Home(w http.ResponseWriter, r *http.Request) {
	var (
		token  *jwt.Token
		claims []byte
		err    error
	)

	if appStorage.Token.AccessToken == "" {
		renderError(w, ErrorDetails{http.StatusBadRequest, "missing access token"})
		return
	}

	parser := new(jwt.Parser)
	if token, _, err = parser.ParseUnverified(appStorage.Token.AccessToken, jwt.MapClaims{}); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("unable to parse token %v", err)})
		return
	}

	if claims, err = json.MarshalIndent(token.Claims, "", "\t"); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("unable to format claims from token %v", err)})
		return
	}

	templ.ExecuteTemplate(w, "bootstrap", map[string]interface{}{"Token": token.Raw, "UsePyron": s.Config.UsePyron, "FormattedClaims": string(claims)})
}

func (s *Server) Resource(w http.ResponseWriter, r *http.Request) {
	var (
		res          *http.Response
		resBodyBytes []byte
		indentedJSON []byte
		err          error
	)

	if appStorage.Token.AccessToken == "" {
		templ.ExecuteTemplate(w, "error", appStorage.Token)
		return
	}

	if res, err = s.fetchResource(); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("client failed to fetch the resource %v", err)})
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 && res.StatusCode != 403 {
		renderError(w, ErrorDetails{http.StatusInternalServerError, fmt.Sprintf("unexpected status code returned from resource server %v", err)})
		return
	}

	if resBodyBytes, err = io.ReadAll(res.Body); err != nil {
		renderError(w, ErrorDetails{http.StatusBadRequest, fmt.Sprintf("unable to fetch the resource %v", err)})
		return
	}

	m := map[string]string{}
	if err = json.Unmarshal(resBodyBytes, &m); err != nil {
		renderError(w, ErrorDetails{http.StatusInternalServerError, fmt.Sprintf("failed to unmarshal response from resource server %v", err)})
		return
	}

	if indentedJSON, err = json.MarshalIndent(m, "", "\t"); err != nil {
		renderError(w, ErrorDetails{http.StatusInternalServerError, fmt.Sprintf("failed to marshal the response %v", err)})
		return
	}

	resourceRes := map[string]interface{}{"Status": res.StatusCode, "Content": string(indentedJSON)}
	templ.ExecuteTemplate(w, "resource", resourceRes)
}

func (s *Server) fetchResource() (res *http.Response, err error) {
	var req *http.Request

	if req, err = s.newHTTPRequest(); err != nil {
		return nil, err
	}

	return s.HttpClient.Do(req)
}

func (s *Server) newHTTPRequest() (req *http.Request, err error) {
	if req, err = http.NewRequest("GET", s.Config.ResourceURL, nil); err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{fmt.Sprintf("Bearer %s", appStorage.Token.AccessToken)},
	}

	// This is for demo purposes only. This can be configured in the environment variables.
	if s.Config.InjectCertMode {
		req.Header.Add("x-ssl-cert-hash", s.Config.XSSLCertHash)
	}

	return req, err
}

type ErrorDetails struct {
	Status  int
	Message string
}

func renderError(w http.ResponseWriter, details ErrorDetails) {
	templ.ExecuteTemplate(w, "error", details)
}
