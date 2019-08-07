package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

// ValidateToken validates and refreshes the given token if needed.
func ValidateToken(config *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	if token.Valid() {
		return token, nil
	}
	tokenSource := config.TokenSource(oauth2.NoContext, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return token, fmt.Errorf("error refreshing token: %v", err)
	}
	return newToken, nil
}

// TokenToFile saves a token to a local json file.
func TokenToFile(path string, token *oauth2.Token) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Unable to save oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
	return nil
}

// TokenFromFile returns a token from a local json file if it exists.
func TokenFromFile(jsonFile string) (*oauth2.Token, error) {
	f, err := os.Open(jsonFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func multipleSave(token *oauth2.Token, paths ...string) {
	for _, p := range paths {
		err := TokenToFile(p, token)
		if err != nil {
			fmt.Println("Error saving to file:", err)
		}
	}
}
