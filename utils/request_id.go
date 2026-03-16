package utils

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIDMiddleware es un middleware de Gin que asegura que cada solicitud tenga un X-Request-ID único.
// Si la solicitud entrante ya contiene el header X-Request-ID, se preserva.
// Si no, se genera un nuevo UUID y se asigna.
// El ID de correlación se propaga en el header de respuesta y se incluye en los logs.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.Request.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Establecer en el header de la request para que ExtractHeaders() lo lea
		c.Request.Header.Set("X-Request-ID", requestID)

		// Establecer en el header de la respuesta para que el caller pueda correlacionar
		c.Writer.Header().Set("X-Request-ID", requestID)

		log.Printf("[%s] %s %s", requestID, c.Request.Method, c.Request.URL.Path)

		c.Next()
	}
}
