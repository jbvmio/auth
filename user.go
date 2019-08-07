package auth

import (
	"encoding/json"
	"log"

	"golang.org/x/oauth2"
)

// UserData .
type UserData struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Verified  bool   `json:"verified_email"`
	userToken *oauth2.Token
}

// GetGoogleUser get UserData from Google.
func GetGoogleUser(userToken *oauth2.Token) UserData {
	b, err := getUserDataFromGoogle(userToken)
	if err != nil {
		log.Fatalf("error retrieving user data: %v\n", err)
	}
	var userData UserData
	err = json.Unmarshal(b, &userData)
	if err != nil {
		log.Fatalf("error marshaling user data: %v\n", err)
	}
	userData.userToken = userToken
	return userData
}
