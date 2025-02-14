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


func ValidateSession(urlapiusuarios string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Permitir que las peticiones a la ruta raíz pasen sin validación
        if c.Request.URL.Path == "/api/v1/dcd/" {
            c.Next()
            return
        }

        // Obtener el header de autorización
        authHeader := c.GetHeader("Authorization")
		csrfToken := c.GetHeader("X-CSRF-Token")
		cookie := c.GetHeader("Cookie")
		path := c.Request.URL.Path

        if authHeader == "" {
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

        req.Header.Set("Authorization", authHeader)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Path", path)

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

func SaveDocuments(file *multipart.FileHeader, email string, urlsavefiles string) string {
	fileContent, err := file.Open()
	if err != nil {
		return ""
	}
	defer fileContent.Close()

	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)
	part, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		return ""
	}
	_, err = io.Copy(part, fileContent)
	if err != nil {
		return ""
	}

	err = writer.WriteField("Kindfile", "documents")
	if err != nil {
		return ""
	}
	err = writer.WriteField("Email", email)
	if err != nil {
		return ""
	}

	writer.Close()

	path, err := makePostRequest(urlsavefiles + "SaveDocuments", reqBody.Bytes(), writer.FormDataContentType())
	if err != nil {
		return ""
	}
	return path
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
    if len(tokenParts) != 2   {
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