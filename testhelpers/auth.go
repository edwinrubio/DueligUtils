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
// Calls POST /api/v1/usuarios/login on DueligUsuarios. Thread-safe.
// baseURL example: "http://localhost:8080"
func LoginJugador(baseURL string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if jugadorToken != "" {
		return jugadorToken, nil
	}
	token, err := loginAt(baseURL, "/api/v1/usuarios/login", "jugador1@duelig.co", "Test1234!")
	if err != nil {
		return "", fmt.Errorf("LoginJugador: %w", err)
	}
	jugadorToken = token
	return jugadorToken, nil
}

// LoginCDO returns a cached JWT for the seeded cdo1@duelig.co.
// Calls POST /api/v1/dcd/login on DueligUsuarios. Thread-safe.
func LoginCDO(baseURL string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if cdoToken != "" {
		return cdoToken, nil
	}
	token, err := loginAt(baseURL, "/api/v1/dcd/login", "cdo1@duelig.co", "Test1234!")
	if err != nil {
		return "", fmt.Errorf("LoginCDO: %w", err)
	}
	cdoToken = token
	return cdoToken, nil
}

// LoginJugadorFull returns both access and refresh tokens for the seeded jugador1@duelig.co.
// Use when a test also needs the refresh token.
func LoginJugadorFull(baseURL string) (accessToken, refreshToken string, err error) {
	return loginAtFull(baseURL, "/api/v1/usuarios/login", "jugador1@duelig.co", "Test1234!")
}

// LoginCDOFull returns both access and refresh tokens for the seeded cdo1@duelig.co.
// Use when a test also needs the refresh token.
func LoginCDOFull(baseURL string) (accessToken, refreshToken string, err error) {
	return loginAtFull(baseURL, "/api/v1/dcd/login", "cdo1@duelig.co", "Test1234!")
}

// ResetTokenCache clears cached tokens. Call between test runs if needed.
func ResetTokenCache() {
	mu.Lock()
	defer mu.Unlock()
	jugadorToken = ""
	cdoToken = ""
}

// loginAt calls the given endpoint with correo/password and returns the access token.
func loginAt(baseURL, endpoint, email, password string) (string, error) {
	access, _, err := loginAtFull(baseURL, endpoint, email, password)
	return access, err
}

// loginAtFull calls the given endpoint with correo/password and returns both tokens.
func loginAtFull(baseURL, endpoint, email, password string) (accessToken, refreshToken string, err error) {
	body, _ := json.Marshal(map[string]string{"correo": email, "password": password})
	resp, httpErr := http.Post(baseURL+endpoint, "application/json", bytes.NewReader(body))
	if httpErr != nil {
		return "", "", httpErr
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("login %s returned %d", endpoint, resp.StatusCode)
	}
	var result struct {
		Token        string `json:"token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&result); decodeErr != nil {
		return "", "", decodeErr
	}
	access := result.AccessToken
	if access == "" {
		access = result.Token
	}
	return access, result.RefreshToken, nil
}
