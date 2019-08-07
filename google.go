package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

const (
	oauthGoogleUserURL  = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	oauthGoogleTokenURL = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="
	defaultCBAddress    = ":31080"
	defaultCBURI        = "/auth/google/callback"
)

// ExampleGoogleScopes .
var ExampleGoogleScopes = []string{
	`email`,
}

// GoogleLogin .
type GoogleLogin struct {
	wg              sync.WaitGroup
	CallbackAddress string
	CallbackURI     string
	genState        string
	authCode        string
	errd            bool
	oathConfig      *oauth2.Config
	Scopes          []string
}

// NewGoogleLogin return a new GoogleLogin with defaults using the provided oauth2 Config.
func NewGoogleLogin(config *oauth2.Config) *GoogleLogin {
	return &GoogleLogin{
		CallbackAddress: defaultCBAddress,
		CallbackURI:     defaultCBURI,
		oathConfig:      config,
		Scopes:          ExampleGoogleScopes,
	}
}

// StartAuth starts the Google OAuth2 Process using a local webserver to handle the callback.
// If a path is given, it will save the returned token to that path, otherwise the token will be printed.
func (g *GoogleLogin) StartAuth(saveTokenPath ...string) {
	token := g.getTokenFromWeb(g.oathConfig)
	j, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}
	multipleSave(token, saveTokenPath...)
	fmt.Printf("Generated Token:\n%s\n", j)
}

// GetTokenFromWeb requests a token from the web, then returns the retrieved token.
func (g *GoogleLogin) getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	server := &http.Server{
		Addr:    g.CallbackAddress,
		Handler: g.oathHandler(),
	}
	g.genState = generateState()
	g.wg.Add(1)
	go g.startHTTP(server)

	authURL := config.AuthCodeURL(g.genState, oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser and follow the prompts:\n%v\n\n", authURL)
	g.wg.Wait()

	if g.errd {
		err := server.Shutdown(context.Background())
		if err != nil {
			log.Fatalf("Error shutting down: %v\n", err)
		}
		log.Fatalln("Error Generating Token.")
	}

	server.Shutdown(context.Background())

	tok, err := config.Exchange(context.TODO(), g.authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}

	return tok
}

func (g *GoogleLogin) startHTTP(server *http.Server) {
	log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Println(err)
	} else {
		log.Println("Server closed!")
	}
}

func (g *GoogleLogin) oathHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(g.CallbackURI, g.oauthGoogleCallback)
	return mux
}

func (g *GoogleLogin) oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	defer g.wg.Done()
	if r.FormValue("state") != g.genState {
		log.Println("invalid oauth google state")
		g.errd = true
		return
	}
	g.authCode = r.FormValue("code")
	fmt.Fprint(w, "code received, this page is no longer needed.")
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func getUserDataFromGoogle(token *oauth2.Token) ([]byte, error) {
	response, err := http.Get(oauthGoogleUserURL + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}
