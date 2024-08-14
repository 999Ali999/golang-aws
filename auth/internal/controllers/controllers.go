package controllers

import (
	"auth/internal/database"
	"auth/internal/types"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"strconv"
	"time"
)

func HelloWorld(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Hello World!"}`))
}

func GetUsers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var users []types.User
	rows, err := database.DB.Query("SELECT * FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user types.User
		if err := rows.Scan(&user.UserId, &user.Username, &user.Password, &user.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	userId, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid user id"}`))
		return
	}

	var user types.User
	query := database.DB.QueryRow("SELECT * FROM users WHERE user_id = $1", userId)
	if err := query.Scan(&user.UserId, &user.Username, &user.Password, &user.CreatedAt); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "User not found"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// testing
	userJSON := r.Header.Get("currentUser")
	if userJSON == "" {
		http.Error(w, "User not found in header", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		http.Error(w, "Error parsing user data", http.StatusInternalServerError)
		return
	}

	// Create a currentUser struct
	currentUser := types.User{
		UserId:    user.UserId,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
	}

	// testing

	// Get the user ID from the URL parameters
	id := r.PathValue("id")
	userId, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid user id"}`))
		return
	}

	// Check if the current user id is as same as the user he is trying to update
	if int64(userId) != currentUser.UserId {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "You are not allowed to update other users"}`))
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid request"}`))
		return
	}
	defer r.Body.Close()

	// Unmarshal the JSON into a User struct
	err = json.Unmarshal(body, &user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid JSON"}`))
		return
	}

	// Hash the user's password before storing it
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	user.Password = string(passwordHash)

	// Update the user in the database
	query := `UPDATE users SET username = $1, password = $2 WHERE user_id = $3 RETURNING user_id, created_at`
	err = database.DB.QueryRow(query, user.Username, user.Password, userId).Scan(&user.UserId, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "User not found"}`))
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with the updated user
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// testing

	userJSON := r.Header.Get("currentUser")
	if userJSON == "" {
		http.Error(w, "User not found in header", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		http.Error(w, "Error parsing user data", http.StatusInternalServerError)
		return
	}

	// Create a currentUser struct
	currentUser := types.User{
		UserId:    user.UserId,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
	}

	// testing

	// Get the user ID from the URL parameters
	id := r.PathValue("id")
	userId, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid user id"}`))
		return
	}

	// Check if the current user id is as same as the user he is trying to update
	if int64(userId) != currentUser.UserId {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "You are not allowed to delete other users"}`))
		return
	}

	// Delete the user from the database
	result, err := database.DB.Exec("DELETE FROM users WHERE user_id = $1", userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the user was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "User not found"}`))
		return
	}

	// Respond with a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "User deleted successfully"}`))
}

// Authentication and Authorization

func Signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid request"}`))
	}
	defer r.Body.Close()

	var user types.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid JSON"}`))
		return
	}
	user.CreatedAt = time.Now()

	// Hash the user's password before storing it
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	user.Password = string(passwordHash)

	query := `INSERT INTO users (username, password, created_at) VALUES ($1, $2, $3) RETURNING user_id`

	err = database.DB.QueryRow(query, user.Username, user.Password, user.CreatedAt).Scan(&user.UserId)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"message": "User already exists"}`))
		return
	}

	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var authInput types.AuthInput

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid request"}`))
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &authInput)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid JSON"}`))
		return
	}

	var userFound types.User
	query := database.DB.QueryRow("SELECT * FROM users WHERE username = $1", authInput.Username)
	if err := query.Scan(&userFound.UserId, &userFound.Username, &userFound.Password, &userFound.CreatedAt); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "User not found"}`))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userFound.Password), []byte(authInput.Password)); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Invalid password"}`))
		return
	}

	generateToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userFound.UserId,
		"username":   userFound.Username,
		"password":   userFound.Password,
		"created_at": userFound.CreatedAt.Format(time.RFC3339),
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
	})

	token, err := generateToken.SignedString([]byte("SECRET"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Failed to generate token"}`))
	}

	response := map[string]string{
		"token": token,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func GetUserProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userJSON := r.Header.Get("currentUser")
	if userJSON == "" {
		http.Error(w, "User not found in header", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		http.Error(w, "Error parsing user data", http.StatusInternalServerError)
		return
	}

	// Create a response struct
	response := struct {
		UserId    int64     `json:"user_id"`
		Username  string    `json:"username"`
		Password  string    `json:"password"`
		CreatedAt time.Time `json:"created_at"`
	}{
		UserId:    user.UserId,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
	}

	formattedJSON, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		http.Error(w, "Error formatting response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(formattedJSON)
}
