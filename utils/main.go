package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// extractHeaders obtiene las cabeceras comunes de autenticación del contexto
func extractHeaders(c *gin.Context) map[string]string {
	return map[string]string{
		"Authorization": c.GetHeader("Authorization"),
		"X-CSRF-Token":  c.GetHeader("X-CSRF-Token"),
		"Cookie":        c.GetHeader("Cookie"),
		"Path":          c.Request.URL.Path,
	}
}

// applyHeaders aplica un conjunto de cabeceras a una solicitud HTTP
func applyHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func ValidateSession(urlapiusuarios string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Permitir que las peticiones a la ruta raíz pasen sin validación
		if c.Request.URL.Path == "/api/v1/dcd/" {
			c.Next()
			return
		}

		// Obtener cabeceras comunes
		headers := extractHeaders(c)

		if headers["Authorization"] == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort()
			return
		}

		// Crear la solicitud para validar el JWT
		req, err := http.NewRequest("POST", urlapiusuarios+"/api/v1/ValidateJWT", nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			c.Abort()
			return
		}

		// Aplicar cabeceras a la solicitud
		applyHeaders(req, headers)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session"})
			c.Abort()
			return
		}
		// defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.JSON(resp.StatusCode, gin.H{"error": string(body)})
			c.Abort()
			return
		}

		c.Next()
	}
}

func makePostRequest(url string, reqBody []byte, kindBody string) (string, error) {
	resp, err := http.Post(url, kindBody, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	var result struct {
		Result string `json:"file_path"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Result, nil
}

func ExtractUserIDFromToken(bearerToken string) (primitive.ObjectID, error) {
	// Obtener el header Authorization

	if bearerToken == "" {
		return primitive.NilObjectID, fmt.Errorf("no authorization header found")
	}

	// Verificar y extraer el token
	tokenParts := strings.Split(bearerToken, " ")
	if len(tokenParts) != 2 {
		return primitive.NilObjectID, fmt.Errorf("invalid token format")
	}

	// Obtener el token
	tokenString := tokenParts[1]

	// Parsear el token sin verificar la firma
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("error parsing token: %v", err)
	}

	// Obtener los claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if userID, exists := claims["_id"]; exists {

			if oid, ok := userID.(string); ok {
				objectID, err := primitive.ObjectIDFromHex(oid)
				if err != nil {
					return primitive.NilObjectID, fmt.Errorf("invalid ObjectID format: %v", err)
				}
				return objectID, nil
			}
			return primitive.NilObjectID, fmt.Errorf("userID is not a valid ObjectID")
		}
		return primitive.NilObjectID, fmt.Errorf("_id not found in token claims")
	}

	return primitive.NilObjectID, fmt.Errorf("invalid token claims")
}

func SaveImageFromUrl(url string, email string, urlsavefiles string) (string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"Url":      url,
		"Kindfile": "images",
		"Email":    email,
	})

	path, err := makePostRequest(urlsavefiles+"ImagesFromUrl", reqBody, "application/json")
	return path, err
}

func SaveFiles(file *multipart.FileHeader, email string, urlsavefiles string, c *gin.Context) (string, error) {
	fileContent, err := file.Open()
	if err != nil {
		return "", err
	}
	defer fileContent.Close()

	// Detectar el tipo de archivo
	buffer := make([]byte, 512)
	_, err = fileContent.Read(buffer)
	if err != nil {
		return "", err
	}

	filekind := GetFileKind(http.DetectContentType(buffer))

	// Resetear el puntero del archivo
	fileContent.Seek(0, io.SeekStart)

	// Crear formulario para c.Request
	err = c.Request.ParseMultipartForm(32 << 20) // 32 MB
	if err != nil {
		return "", err
	}

	// Preparar la solicitud al servicio de archivos
	req, err := http.NewRequest("POST", urlsavefiles+"Save"+filekind, nil)
	if err != nil {
		return "", err
	}

	// Obtener y aplicar cabeceras comunes
	headers := extractHeaders(c)
	applyHeaders(req, headers)

	// Crear un nuevo formulario multipart
	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)
	part, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(part, fileContent)
	if err != nil {
		return "", err
	}

	err = writer.WriteField("Kindfile", filekind)
	if err != nil {
		return "", err
	}
	err = writer.WriteField("Email", email)
	if err != nil {
		return "", err
	}

	writer.Close()

	// Establecer el tipo de contenido
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Body = io.NopCloser(&reqBody)
	req.ContentLength = int64(reqBody.Len())

	// Hacer la solicitud HTTP
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Verificar la respuesta
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	var result struct {
		Result string `json:"file_path"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Result, nil
}

func GetFileKind(fileType string) string {
	// Tipos MIME comunes para imágenes
	imageTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"image/tiff",
	}

	// Verificar si es una imagen
	for _, imgType := range imageTypes {
		if fileType == imgType {
			return "Images"
		}
	}

	// Verificar si es un PDF
	if fileType == "application/pdf" {
		return "Documents"
	}

	// Si no es ninguno de los tipos admitidos
	return ""
}

// CORSMiddleware configura los encabezados necesarios para permitir peticiones CORS
func CORSMiddleware(cors_urls string) gin.HandlerFunc {
	return func(c *gin.Context) {

		allowedOrigins := strings.Split(cors_urls, ",")
		origin := c.Request.Header.Get("Origin")

		// Verifica si el origen está en la lista de permitidos
		for _, allowedOrigin := range allowedOrigins {
			if strings.TrimSpace(allowedOrigin) == origin {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Origin, Cache-Control, X-Requested-With, client-type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
