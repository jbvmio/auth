package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

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
