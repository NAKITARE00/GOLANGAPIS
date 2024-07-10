package main

import (
	"NIDA/configs"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	dbase "NIDA/db"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)



func main() {
	//Auto migrate tables

	cfg := initCFG()
	
	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		log.Fatal(err)
	}
	
	initStorage(db)

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func initStorage (db *sql.DB) {
	err := db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Successfully connected to database")
}

func initCFG() mysql.Config{
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
	
		return cfg
}

func run() error {
	cfg, err := ReadConfig("conf.json")
	if err != nil {
		return err
	}

	handlers := Handlers{Config: cfg}
	router := gin.Default()
	router.POST("/verify", verifyHandler)
	router.POST("/verify/v2", handlers.verify)
	router.POST("/register", registerMerchant)
	return router.Run(":8080")
}

type Config struct {
	UserID                string
	NidaURL               string
	MessageSecurityPubKey *rsa.PublicKey
	StakeholderPrivKey    *rsa.PrivateKey
}

func ReadConfig(filename string) (*Config, error) {
	bs, err := os.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	var rawCfg struct {
		UserID                string `json:"user_id"`
		NidaURL               string `json:"nida_url"`
		MessageSecurityPubKey string `json:"message_security_pub_key"`
		StakeholderPrivKey    string `json:"stakeholder_priv_key"`
	}
	if err := json.Unmarshal(bs, &rawCfg); err != nil {
		return nil, err
	}

	pubkeybs, err := os.ReadFile(rawCfg.MessageSecurityPubKey)
	if err != nil {
		return nil, err
	}

	pubkeyBlock, _ := pem.Decode(pubkeybs)
	cert, err := x509.ParseCertificate(pubkeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected rsa public key but got %T", cert.PublicKey)
	}

	privkeybs, err := os.ReadFile(rawCfg.StakeholderPrivKey)
	if err != nil {
		return nil, err
	}

	privkeyBlock, _ := pem.Decode(privkeybs)
	privKey, err := x509.ParsePKCS1PrivateKey(privkeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("expected rsa private key but got %T", cert.PublicKey)
	}

	return &Config{
		UserID:                rawCfg.UserID,
		NidaURL:               rawCfg.NidaURL,
		MessageSecurityPubKey: pubKey,
		StakeholderPrivKey:    privKey,
	}, nil
}
