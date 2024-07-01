package main

import (
	dbase "NIDA/db"
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)

type ResponseHeader struct {
	Id        string    `xml:"Id"`
	TimeStamp time.Time `xml:"TimeStamp"`
}

type ResponseBody struct {
	CryptoInfo ResponseCryptoInfo `json:"cryptInfo" xml:"CryptoInfo"`
	Payload    string             `json:"payload" xml:"Payload"`
	Signature  string             `json:"signature" xml:"Signature"`
}

type StatusSectionBase struct {
	Code int `xml:"Code"`
}

type RQVerificationResult struct {
	XMLName xml.Name         `xml:"RQVerificationResult"`
	Header  ResponseHeader   `xml:"Header"`
	Body    ResponseBody     `xml:"Body"`
	Status  StatusSectionBase `xml:"Status"`
}

type Question struct {
	NIN      string `json:"nin" binding:"required"`
	Question string `json:"question" binding:"required"`
}

func retrieveMerchantDetails(c *gin.Context, cfg mysql.Config) (merchantID string, err error) {
	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		return "", err
	}
	defer db.Close()

	// query to get merchant details
	query := "SELECT merchant_name, merchant_id FROM merchants WHERE some_condition = ?"
	var name, id string
	err = db.QueryRow(query, "some_value").Scan(&name, &id)
	if err != nil {
		return "", err
	}

	return id, nil
}

func requestQuestionFromNIDA(c *gin.Context, r *http.Request, cfg mysql.Config) (RQVerificationResult, error) {
	//Retrieve merchant details

	nin, err := retrieveMerchantDetails(c, cfg)

	if err != nil {
		return RQVerificationResult{}, err
	}
	
	// Create the XML payload
	requestPayload := fmt.Sprintf(`<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		<soap:Header>
			<Id></Id>
			<TimeStamp>%s</TimeStamp>
			<ClientNameorIP>%s</ClientNameorIP>
			<UserID>%s</UserID>
		</soap:Header>
		<soap:Body>
			<CryptoInfo>
				<EncryptedCryptoKey>%s</EncryptedCryptoKey>
				<EncryptedCryptoIV>%s</EncryptedCryptoIV>
			</CryptoInfo>
			<Payload>
				%s
			</Payload>
			<Signature>%s</Signature>
		</soap:Body>
	</soap:Envelope>`, time.Now().Format(time.RFC3339), r.RemoteAddr, "UserID", "EncryptedCryptoKey", "EncryptedCryptoIV", nin, "Signature")

	// NIDA API endpoint
	resp, err := http.Post("https://nacer01/TZ_CIG/GatewayService.svc?wsdl", "text/xml", bytes.NewBufferString(requestPayload))
	if err != nil {
		return RQVerificationResult{}, err
	}
	defer resp.Body.Close()

	// Parse the response
	var responseEnvelope struct {
		Body struct {
			Response RQVerificationResult `xml:"RQVerificationResult"`
		} `xml:"Body"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&responseEnvelope); err != nil {
		return RQVerificationResult{}, err
	}

	return responseEnvelope.Body.Response, nil
}

func storeQuestion (c *gin.Context, cfg mysql.Config) {
	var question Question
	if err := c.ShouldBindJSON(&question); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Add question to the database
	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO questions (nin, question) VALUES (?, ?)", question.NIN, question.Question)

	c.JSON(http.StatusOK, gin.H{"message": "Question stored successfully"})
}

func verifyAnswerWithNIDA(nin, rqCode, answer string) (RQVerificationResult, error) {
	// Create the XML payload
	requestPayload := fmt.Sprintf(`<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		<soap:Header>
			<Id></Id>
			<TimeStamp>%s</TimeStamp>
			<ClientNameorIP>%s</ClientNameorIP>
			<UserID>%s</UserID>
		</soap:Header>
		<soap:Body>
			<CryptoInfo>
				<EncryptedCryptoKey>%s</EncryptedCryptoKey>
				<EncryptedCryptoIV>%s</EncryptedCryptoIV>
			</CryptoInfo>
			<Payload>
				<NIN>%s</NIN>
				<RQCode>%s</RQCode>
				<QNANSW>%s</QNANSW>
			</Payload>
			<Signature>%s</Signature>
		</soap:Body>
	</soap:Envelope>`, time.Now().Format(time.RFC3339), "ClientIP", "UserID", "EncryptedCryptoKey", "EncryptedCryptoIV", nin, rqCode, answer, "Signature")

	// Sendi the request to NIDA
	resp, err := http.Post("https://nacer01/TZ_CIG/GatewayService.svc?wsdl", "text/xml", bytes.NewBufferString(requestPayload))
	if err != nil {
		return RQVerificationResult{}, err
	}
	defer resp.Body.Close()

	// Parse the response
	var responseEnvelope struct {
		Body struct {
			Response RQVerificationResult `xml:"RQVerificationResult"`
		} `xml:"Body"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&responseEnvelope); err != nil {
		return RQVerificationResult{}, err
	}

	return responseEnvelope.Body.Response, nil
}
