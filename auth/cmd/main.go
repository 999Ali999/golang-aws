package main

import (
	"auth/internal/server"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver
)

func main() {
	newServer := server.NewServer()

	err := newServer.ListenAndServe()
	if err != nil {
		panic(fmt.Sprintf("cannot start newServer: %s", err))
	}
}
