package testhelpers

import (
	"fmt"
	"net/http"
	"time"
)

// WaitForHealth polls baseURL+"/health" until it returns 200 or timeout.
// timeout is in seconds. Returns error if timeout exceeded.
func WaitForHealth(baseURL, serviceName string, timeoutSeconds int) error {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("service %s did not become healthy within %ds", serviceName, timeoutSeconds)
}

// WaitForAllServices calls WaitForHealth for all 5 test services.
// Returns the first error encountered, or nil if all are healthy.
func WaitForAllServices() error {
	services := []struct{ name, url string }{
		{"usuarios", "http://localhost:8080"},
		{"savefiles", "http://localhost:8081"},
		{"cd", "http://localhost:8082"},
		{"reservas", "http://localhost:8084"},
		{"notificaciones", "http://localhost:8085"},
	}
	for _, svc := range services {
		if err := WaitForHealth(svc.url, svc.name, 60); err != nil {
			return err
		}
	}
	return nil
}
