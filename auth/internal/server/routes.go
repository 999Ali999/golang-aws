package server

import (
	"auth/internal/controllers"
	"auth/internal/middlewares"
	"net/http"
)

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("GET /hello", controllers.HelloWorld)

	//mux.Handle("/", http.HandlerFunc(controllers.HelloWorld))

	mux.HandleFunc("POST /login", controllers.Login)
	mux.HandleFunc("GET /users", controllers.GetUsers)
	mux.HandleFunc("GET /users/{id}", controllers.GetUser)
	mux.HandleFunc("POST /signup", controllers.Signup)

	// Protected routes
	mux.Handle("GET /users/profile", middlewares.CheckAuth(http.HandlerFunc(controllers.GetUserProfile)))
	mux.Handle("PUT /users/{id}", middlewares.CheckAuth(http.HandlerFunc(controllers.UpdateUser)))
	mux.Handle("DELETE /users/{id}", middlewares.CheckAuth(http.HandlerFunc(controllers.DeleteUser)))

	return mux
}
