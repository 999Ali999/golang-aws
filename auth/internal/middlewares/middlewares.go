package middlewares

import (
	"auth/internal/database"
	"auth/internal/types"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
)

func CheckAuth(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authorization header is missing"))
			return
		}

		authToken := strings.Split(authHeader, " ")
		if len(authToken) != 2 || authToken[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid token format"))
			return
		}

		tokenString := authToken[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("SECRET"), nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid or expired token"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid token"))
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Token expired"))
			return
		}

		// Safely extract user information from claims
		var user types.User

		if userId, ok := claims["user_id"].(float64); ok {
			user.UserId = int64(userId)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid user_id in token"))
			return
		}

		query := database.DB.QueryRow("SELECT * FROM users WHERE user_id = $1", user.UserId)
		if err := query.Scan(&user.UserId, &user.Username, &user.Password, &user.CreatedAt); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message": "User not found"}`))
			return
		}

		// Convert user to JSON
		userJSON, err := json.Marshal(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error processing user data"))
			return
		}

		// Set the user information in the request header
		r.Header.Set("currentUser", string(userJSON))

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}
