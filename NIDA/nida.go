package main

import (
	dbase "NIDA/db"
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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


// func retrieveMerchantDetails(nin int) (Merchant, error) {
// 	// Retrieve cfg database configuration
// 	cfg := initCFG()

// 	db, err := dbase.NewMySQLStorage(cfg)
// 	if err != nil {
// 		return Merchant{}, err
// 	}
// 	defer db.Close()

// 	// Query to get merchant details
// 	query := "SELECT merchant_name, merchant_id FROM merchants WHERE nin = ?"
// 	var name, id string
// 	err = db.QueryRow(query, nin).Scan(&name, &id)
// 	if err != nil {
// 		return Merchant{}, err
// 	}

// 	return Merchant{FirstName: name, LastName: "LastName", Telephone: "Telephone", NIN: id, Email: "Email"}, nil
// }



func requestQuestionFromNIDA(c *gin.Context, r *http.Request, nin string) (RQVerificationResult, error) {
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

	storeQuestion(Question{NIN: nin, Question: responseEnvelope.Body.Response.Body.Payload}, c)

	return responseEnvelope.Body.Response, nil
}

func storeQuestion(q Question, c *gin.Context) {
	// Retrieve cfg database configuration
	cfg := initCFG()

	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Add question to the database
	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO questions (nin, question) VALUES (?, ?)", q.NIN, q.Question)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Question already exists"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

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
