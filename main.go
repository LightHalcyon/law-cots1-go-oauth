package main

import (
	"net/http"
	// "net/url"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
)

type AuthData struct {
	Username string
	Password string
}

type UserDatabase struct {
	FullName string
	Password string
}

type TokenDetails struct {
	Username     string
	ClientID     string
	RefreshToken string
	Expires      time.Time
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

var dbToken *cache.Cache
var userDb map[string]UserDatabase
var clientDb map[string]string

func TokenGenerator() string {
	b := make([]byte, 18)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func Token(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		AccessToken  string  `json:"access_token"`
		ExpiresIn    int     `json:"expires_in"`
		TokenType    string  `json:"token_type"`
		Scope        *string `json:"user_id"`
		RefreshToken string  `json:"refresh_token"`
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorResp := ErrorResponse{
			Error:       "invalid_form",
			Description: "Form salah",
		}
		json.NewEncoder(w).Encode(errorResp)
	} else {
		if val, ok := userDb[r.Form["username"][0]]; !ok || val.Password != r.Form["password"][0] {
			w.WriteHeader(http.StatusUnauthorized)
			errorResp := ErrorResponse{
				Error:       "invalid_request",
				Description: "Form value tidak valid",
			}
			json.NewEncoder(w).Encode(errorResp)
		} else if val, ok := clientDb[r.Form["client_id"][0]]; !ok || val != r.Form["client_secret"][0] || r.Form["grant_type"][0] != "password" {
			w.WriteHeader(http.StatusUnauthorized)
			errorResp := ErrorResponse{
				Error:       "invalid_request",
				Description: "Form value tidak valid",
			}
			json.NewEncoder(w).Encode(errorResp)
		} else {
			response := Response{
				AccessToken:  TokenGenerator(),
				ExpiresIn:    300,
				TokenType:    "Bearer",
				Scope:        nil,
				RefreshToken: TokenGenerator(),
			}
			tokenDetails := TokenDetails{
				Username:     r.Form["username"][0],
				ClientID:     r.Form["client_id"][0],
				RefreshToken: response.RefreshToken,
				Expires:      time.Now().Local().Add(time.Minute * 5),
			}
			dbToken.Set(response.AccessToken, tokenDetails, cache.DefaultExpiration)
			json.NewEncoder(w).Encode(response)
		}
	}
}

func Resource(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		AccessToken  string `json:"access_token"`
		ClientID     string `json:"client_id"`
		UserID       string `json:"user_id"`
		FullName     string `json:"full_name"`
		Expires      int    `json:"expires"`
		RefreshToken string `json:"refresh_token"`
	}

	authToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
	tokenDetails, found := dbToken.Get(authToken)
	if !found {
		w.WriteHeader(http.StatusUnauthorized)
		errorResp := ErrorResponse{
			Error:       "invalid_token",
			Description: "Token salah/expired",
		}
		json.NewEncoder(w).Encode(errorResp)
	} else {
		if tokenData, ok := tokenDetails.(TokenDetails); ok {
			if time.Now().After(tokenData.Expires) {
				w.WriteHeader(http.StatusUnauthorized)
				errorResp := ErrorResponse{
					Error:       "invalid_token",
					Description: "Token salah/expired",
				}
				json.NewEncoder(w).Encode(errorResp)
			} else {
				response := Response{
					AccessToken:  authToken,
					ClientID:     tokenData.ClientID,
					UserID:       tokenData.Username,
					FullName:     userDb[tokenData.Username].FullName,
					Expires:      int(tokenData.Expires.Sub(time.Now()).Seconds()),
					RefreshToken: tokenData.RefreshToken,
				}
				json.NewEncoder(w).Encode(response)
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			errorResp := ErrorResponse{
				Error:       "read_db_fail",
				Description: "Kesalahan dalam membaca database",
			}
			json.NewEncoder(w).Encode(errorResp)
		}
	}
}

func init() {
	userDb = make(map[string]UserDatabase)
	clientDb = make(map[string]string)
	dbToken = cache.New(5*time.Minute, 10*time.Minute)
	userDb["1406568753"] = UserDatabase{
		Password: "topnep123",
		FullName: "Adityawarman Fanaro",
	}
	clientDb["11a1"] = "12919a"
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/oauth/token", Token).Methods("POST")
	router.HandleFunc("/oauth/resource", Resource).Methods("GET")

	log.Fatal(http.ListenAndServe("0.0.0.0:20604", router))
}
