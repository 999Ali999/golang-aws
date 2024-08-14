package server

import (
	"auth/internal/database"
	"database/sql"
	"net/http"
)

type Server struct {
	db *sql.DB
}

func NewServer() *http.Server {
	newServer := &Server{
		db: database.Connect(),
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: newServer.RegisterRoutes(),
	}

	return server
}
