package database

import (
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver
	"log"
)

var DB *sql.DB

func Connect() *sql.DB {
	connStr := "postgres://postgres:ali.sh.81@database-1.cb4yiqgg0f3u.eu-north-1.rds.amazonaws.com/mydb?sslmode=disable"
	var err error
	DB, err = sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal(err)
	}
	return DB
}
