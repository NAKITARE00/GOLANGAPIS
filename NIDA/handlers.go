package main

import (
	dbase "NIDA/db"
	"encoding/xml"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)

type RequestHeader struct {
	Id         string    `json:"id"`
	TimeStamp  time.Time `json:"timestamp"`
	ClientName string    `json:"clientName"`
	UserID     string    `json:"userId"`
}

type RequestBody struct {
	CryptoInfo ResponseCryptoInfo `json:"cryptoInfo"`
	Payload    string             `json:"payload"`
	Signature  string             `json:"signature"`
}

type IRequest struct {
	Header RequestHeader `json:"header"`
	Body   RequestBody   `json:"body"`
}

type Merchant struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Telephone string `json:"telephone"`
	NIN       string `json:"NIN"`
	Email     string `json:"email"`
}

func verifyHandler(c *gin.Context) {
	var request IRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Decrypt the AES key and IV using RSA
	aesKey, aesIV, err := decryptCryptoInfo(request.Body.CryptoInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt crypto info"})
		return
	}

	// Decrypt the payload using the AES key and IV
	decryptedPayload, err := decryptPayload(request.Body.Payload, aesKey, aesIV)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt payload"})
		return
	}

	// Parse the XML payload to get the NIN
	var payload struct {
		XMLName xml.Name `xml:"Payload"`
		NIN     string   `xml:"NIN"`
	}
	if err := xml.Unmarshal([]byte(decryptedPayload), &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Request the first question from NIDA
	questionResponse, err := requestQuestionFromNIDA(r, payload.NIN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send the question back to the client
	c.JSON(http.StatusOK, gin.H{"question": questionResponse})
}

func registerMerchant(c *gin.Context, cfg mysql.Config) {
	var merchant Merchant
	if err := c.ShouldBindJSON(&merchant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Add merchant to the database
	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO merchants (firstName, lastName, telephone, NIN, email) VALUES (?, ?, ?, ?, ?)", merchant.FirstName, merchant.LastName, merchant.Telephone, merchant.NIN, merchant.Email)

	c.JSON(http.StatusOK, gin.H{"message": "Merchant registered successfully"})
}