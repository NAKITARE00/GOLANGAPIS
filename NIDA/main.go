package main

import (
	"NIDA/configs"
	"database/sql"
	"log"

	dbase "NIDA/db"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)

func main() {
	// Auto migrate tables
	cfg := mysql.Config{
		User:                 configs.Envs.DBUser,
		Passwd:               configs.Envs.DBPassword,
		Addr:                 configs.Envs.DBAddress,
		DBName:               configs.Envs.DBName,
		Net:                  "tcp",
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		log.Fatal(err)
	}

	initStorage(db)

	router := gin.Default()
	router.POST("/verify", verifyHandler)
	router.Run(":8080")
}

func initStorage (db *sql.DB) {
	err := db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Successfully connected to database")
}