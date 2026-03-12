package testhelpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

var (
	jugadorToken string
	cdoToken     string
	mu           sync.Mutex
)

// LoginJugador returns a cached JWT for the seeded jugador1@duelig.co.
// Calls POST /api/v1/login on DueligUsuarios. Thread-safe.
// baseURL example: "http://localhost:8080"
func LoginJugador(baseURL string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if jugadorToken != "" {
		return jugadorToken, nil
	}
	token, err := login(baseURL, "jugador1@duelig.co", "Test1234!")
	if err != nil {
		return "", fmt.Errorf("LoginJugador: %w", err)
	}
	jugadorToken = token
	return jugadorToken, nil
}

// LoginCDO returns a cached JWT for the seeded cdo1@duelig.co.
func LoginCDO(baseURL string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if cdoToken != "" {
		return cdoToken, nil
	}
	token, err := login(baseURL, "cdo1@duelig.co", "Test1234!")
	if err != nil {
		return "", fmt.Errorf("LoginCDO: %w", err)
	}
	cdoToken = token
	return cdoToken, nil
}

// ResetTokenCache clears cached tokens. Call between test runs if needed.
func ResetTokenCache() {
	mu.Lock()
	defer mu.Unlock()
	jugadorToken = ""
	cdoToken = ""
}

func login(baseURL, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(baseURL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login returned %d", resp.StatusCode)
	}
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Token != "" {
		return result.Token, nil
	}
	return result.AccessToken, nil
}
