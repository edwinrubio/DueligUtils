package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// extractHeaders obtiene las cabeceras comunes de autenticación del contexto
func ExtractHeaders(c *gin.Context) map[string]string {
	return map[string]string{
		"Authorization": c.GetHeader("Authorization"),
		"X-CSRF-Token":  c.GetHeader("X-CSRF-Token"),
		"Cookie":        c.GetHeader("Cookie"),
		"Client-Type":   c.GetHeader("Client-Type"),
		"Path":          c.Request.URL.Path,
	}
}

// applyHeaders aplica un conjunto de cabeceras a una solicitud HTTP
func ApplyHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func ValidateSession(urlapiusuarios string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Obtener cabeceras comunes
		headers := ExtractHeaders(c)

		if headers["Authorization"] == "" {
			log.Println("Missing Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort()
			return
		}

		if headers["Client-Type"] == "" {
			log.Println("Missing Client header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Client header"})
			c.Abort()
			return
		}

		// Crear la solicitud para validar el JWT
		req, err := http.NewRequest("POST", urlapiusuarios+"/api/v1/ValidateJWT", nil)
		if err != nil {
			log.Println("Error creating ValidateJWT request:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			c.Abort()
			return
		}

		// Aplicar cabeceras a la solicitud
		ApplyHeaders(req, headers)

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

func ExtractUserIDFromToken(tokenString string) (primitive.ObjectID, error) {
	// Si tokenString empieza con Bearer (cualquier variación), sobreescribirlo
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tokenString)), "bearer") {
		cleanToken, err := GetTokenFromBearerString(tokenString)
		if err != nil {
			return primitive.NilObjectID, fmt.Errorf("error extracting token from bearer string: %v", err)
		}
		tokenString = cleanToken
	}

	// Parsear el token sin verificar la firma
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		log.Println("Error parsing token:", err)
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

func GetTokenFromBearerString(bearerToken string) (string, error) {
	if bearerToken == "" {
		return "", fmt.Errorf("no authorization header found")
	}

	// Verificar y extraer el token
	tokenParts := strings.Split(bearerToken, " ")
	if len(tokenParts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	// Obtener el token
	tokenString := tokenParts[1]

	return tokenString, nil
}

// Esta funcion es para guardar imagenes desde una URL de google o facebook
// Se usa para guardar la imagen de perfil del usuario
// Se espera que la URL sea una imagen valida y que el email sea el del usuario
func SaveImageFromUrl(url string, acl string, urlsavefiles string) (string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"Url":      url,
		"Kindfile": "images",
		"Acl":      acl,
	})

	path, err := makePostRequest(urlsavefiles+"ImagesFromUrl", reqBody, "application/json")
	return path, err
}

// getContentTypeFromExtension detecta el Content-Type correcto basándose en la extensión del archivo
func getContentTypeFromExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	
	contentTypes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".bmp":  "image/bmp",
		".ico":  "image/x-icon",
		".tiff": "image/tiff",
		".tif":  "image/tiff",
		".pdf":  "application/pdf",
	}
	
	if contentType, exists := contentTypes[ext]; exists {
		return contentType
	}
	
	return "application/octet-stream"
}

// createMultipartFormData crea el formulario multipart común para ambos tipos de archivo
func createMultipartFormData(file *multipart.FileHeader, kindfile string) (*bytes.Buffer, *multipart.Writer, error) {
	fileContent, err := file.Open()
	if err != nil {
		return nil, nil, err
	}
	defer fileContent.Close()

	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)

	// Detectar el Content-Type correcto basado en la extensión del archivo
	contentType := getContentTypeFromExtension(file.Filename)
	
	// Crear el campo 'file' con el Content-Type explícito
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="` + file.Filename + `"`}
	h["Content-Type"] = []string{contentType}
	
	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, nil, err
	}

	_, err = io.Copy(part, fileContent)
	if err != nil {
		return nil, nil, err
	}

	// Agregar el campo Kindfile
	err = writer.WriteField("Kindfile", kindfile)
	if err != nil {
		return nil, nil, err
	}

	writer.Close()
	return &reqBody, writer, nil
}

// executeFileUploadRequest realiza la petición HTTP común para subir archivos
func executeFileUploadRequest(url string, body *bytes.Buffer, writer *multipart.Writer, c *gin.Context) (string, error) {
	// Preparar la solicitud al servicio de archivos
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}

	// Obtener y aplicar cabeceras comunes
	headers := ExtractHeaders(c)
	ApplyHeaders(req, headers)

	// Establecer el tipo de contenido
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Body = io.NopCloser(body)
	req.ContentLength = int64(body.Len())

	// Hacer la solicitud HTTP
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Verificar la respuesta
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("received non-OK HTTP status: %s, response: %s", resp.Status, string(bodyBytes))
	}

	var result struct {
		Result string `json:"file_path"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Result, nil
}

// detectFileKind detecta el tipo de archivo basándose en contenido y extensión
func detectFileKind(file *multipart.FileHeader) (string, error) {
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

	contentType := http.DetectContentType(buffer)
	return GetFileKind(contentType, file.Filename), nil
}

///////////////////////////////////////////////////////////////
//				Seccion de manejo de archivos
///////////////////////////////////////////////////////////////

func SaveFiles(urlsavefiles string, c *gin.Context, Filename string) (string, error) {

	file, err := c.FormFile(Filename)
	if err != nil {
		log.Println("Error al obtener el archivo del formulario:", err)
		return "", err
	}

	// Si la URL contiene "Images" o "SavePrivateImages", forzar el tipo como imagen
	if strings.Contains(urlsavefiles, "Images") || strings.Contains(urlsavefiles, "SavePrivateImages") {
		return SaveFilesAsImage(file, urlsavefiles, c)
	}

	// Detectar el tipo de archivo automáticamente
	filekind, err := detectFileKind(file)
	if err != nil {
		log.Println("Error al detectar el tipo de archivo:", err)
		return "", err
	}

	// Crear el formulario multipart
	reqBody, writer, err := createMultipartFormData(file, filekind)
	if err != nil {
		log.Println("Error al crear el formulario multipart:", err)
		return "", err
	}

	// Construir la URL completa con el endpoint específico
	fullURL := urlsavefiles

	// Ejecutar la petición
	path, err := executeFileUploadRequest(fullURL, reqBody, writer, c)
	if err != nil {
		log.Println("Error al guardar el archivo:", err)
		log.Println("URL utilizada:", fullURL)
		return "", err
	}

	return path, nil
}

func SaveFilesAsImage(file *multipart.FileHeader, urlsavefiles string, c *gin.Context) (string, error) {
	// Validar que es una imagen por extensión antes de enviar
	ext := strings.ToLower(filepath.Ext(file.Filename))
	imageExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
		".svg":  true,
		".tiff": true,
		".tif":  true,
		".bmp":  true,
		".ico":  true,
	}

	if !imageExtensions[ext] {
		return "", fmt.Errorf("el archivo debe ser una imagen válida, extensión recibida: %s", ext)
	}

	// Crear el formulario multipart usando la función auxiliar
	reqBody, writer, err := createMultipartFormData(file, "Images")
	if err != nil {
		return "", err
	}

	// Ejecutar la petición usando la función auxiliar
	return executeFileUploadRequest(urlsavefiles, reqBody, writer, c)
}

func DeleteFile(filePath string, domain_server string, c *gin.Context) error {
	// Preparar la solicitud al servicio de archivos
	req, err := http.NewRequest("DELETE", domain_server+"?file_path="+filePath, nil)
	if err != nil {
		log.Println("Error al crear la solicitud:", err)
		return fmt.Errorf("error al crear la solicitud: %v", err)
	}

	// Obtener y aplicar cabeceras comunes desde el contexto de Gin
	headers := ExtractHeaders(c)
	ApplyHeaders(req, headers)

	// Hacer la solicitud HTTP
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error al realizar la petición: %v", err)
	}
	defer resp.Body.Close()

	// Verificar la respuesta
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error del servidor al eliminar el archivo: %s - %s", resp.Status, string(bodyBytes))
	}

	return nil
}

// GetFileKindImproved mejora la detección de tipos de archivo combinando MIME type y extensión
func GetFileKind(contentType string, filename string) string {
	// Primero verificar por extensión de archivo
	ext := strings.ToLower(filepath.Ext(filename))

	// Extensiones de imagen comunes
	imageExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
		".svg":  true,
		".tiff": true,
		".tif":  true,
		".bmp":  true,
		".ico":  true,
	}

	// Si la extensión indica que es una imagen, retornar "Images"
	if imageExtensions[ext] {
		return "Images"
	}

	// Verificar por tipo MIME
	imageTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"image/tiff",
		"image/jpg",
		"image/bmp",
		"image/x-icon",
	}

	for _, imgType := range imageTypes {
		if contentType == imgType {
			return "Images"
		}
	}

	// Verificar si es un PDF
	if contentType == "application/pdf" || ext == ".pdf" {
		return "Documents"
	}

	// Si no se puede determinar, verificar si la URL sugiere que es para imágenes
	return ""
}

// UpdateFile actualiza un archivo siguiendo el orden: 1. Guardar nuevo archivo, 2. Eliminar archivo viejo
// Parámetros:
// - file: El nuevo archivo a guardar (multipart.FileHeader)
// - oldFilePath: La ruta del archivo viejo que se va a eliminar
// - url: URL del servicio donde guardar el nuevo archivo
// - g: Contexto de Gin
// Retorna la ruta del nuevo archivo guardado
func UpdateFile(FileNameHeader string, oldFilePath string, urlSaveFile string, urlDeleteFile string, g *gin.Context) (string, error) {
	// Paso 1: Guardar el nuevo archivo
	log.Printf("Guardando nuevo archivo: %s", FileNameHeader)
	newFilePath, err := SaveFiles(urlSaveFile, g, FileNameHeader)
	if err != nil {
		log.Printf("Error al guardar el nuevo archivo: %v", err)
		return "", fmt.Errorf("error al guardar el nuevo archivo: %v", err)
	}

	log.Printf("Nuevo archivo guardado exitosamente en: %s", newFilePath)

	// Paso 2: Eliminar el archivo viejo (solo si se guardó exitosamente el nuevo)
	if oldFilePath != "" {
		log.Printf("Eliminando archivo viejo: %s", oldFilePath)
		err = DeleteFile(oldFilePath, urlDeleteFile, g)
		if err != nil {
			log.Printf("Advertencia: No se pudo eliminar el archivo viejo '%s': %v", oldFilePath, err)
			// No retornamos error aquí porque el nuevo archivo ya se guardó exitosamente
			// Solo logueamos la advertencia
		} else {
			log.Printf("Archivo viejo eliminado exitosamente: %s", oldFilePath)
		}
	}

	return newFilePath, nil
}

///////////////////////////////////////////////////////////////
//				Seccion de manejo de CORS
///////////////////////////////////////////////////////////////

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
