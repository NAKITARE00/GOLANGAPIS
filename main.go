package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NAKITAREOO/GOLANGAPIS/configs"
	database "github.com/NAKITAREOO/GOLANGAPIS/db"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)

// RSA private key is stored in a PEM file
const privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsomeb64base64encodedRSAprivatekeydata
-----END RSA PRIVATE KEY-----`

type RequestHeader struct {
	Id          string    `json:"id"`
	TimeStamp   time.Time `json:"timestamp"`
	ClientName  string    `json:"clientName"`
	UserID      string    `json:"userId"`
}

type RequestBody struct {
	CryptoInfo struct {
		EncryptedCryptoKey string `json:"encryptedCryptoKey"`
		EncryptedCryptoIV  string `json:"encryptedCryptoIV"`
	} `json:"cryptoInfo"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type IRequest struct {
	Header RequestHeader `json:"header"`
	Body   RequestBody   `json:"body"`
}

type ResponseHeader struct {
	Id        string    `xml:"Id"`
	TimeStamp time.Time `xml:"TimeStamp"`
}

type ResponseCryptoInfo struct {
	EncryptedCryptoKey string `xml:"EncryptedCryptoKey"`
	EncryptedCryptoIV  string `xml:"EncryptedCryptoIV"`
}

type ResponseBody struct {
	CryptoInfo ResponseCryptoInfo `xml:"CryptoInfo"`
	Payload    string             `xml:"Payload"`
	Signature  string             `xml:"Signature"`
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

	db, err := database.NewMySQLStorage(cfg)
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
	questionResponse, err := requestQuestionFromNIDA(payload.NIN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send the question back to the client
	c.JSON(http.StatusOK, gin.H{"question": questionResponse})
}

func decryptCryptoInfo(cryptoInfo struct {
	EncryptedCryptoKey string `json:"encryptedCryptoKey"`
	EncryptedCryptoIV  string `json:"encryptedCryptoIV"`
}) ([]byte, []byte, error) {
	// Decode the base64 encrypted AES key and IV
	encryptedAESKey, err := base64.StdEncoding.DecodeString(cryptoInfo.EncryptedCryptoKey)
	if err != nil {
		return nil, nil, err
	}
	encryptedAESIV, err := base64.StdEncoding.DecodeString(cryptoInfo.EncryptedCryptoIV)
	if err != nil {
		return nil, nil, err
	}

	// Parse the RSA private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt the AES key and IV using RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		return nil, nil, err
	}
	aesIV, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESIV, nil)
	if err != nil {
		return nil, nil, err
	}

	return aesKey, aesIV, nil
}

func decryptPayload(payload string, aesKey, aesIV []byte) (string, error) {
	// Decode the base64 encrypted payload
	encryptedPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Use CBC mode
	ciphertext := encryptedPayload
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := aesIV
	ciphertext = ciphertext[aes.BlockSize:]

	// Decrypt the payload
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted payload (assuming PKCS7 padding)
	paddingLength := int(ciphertext[len(ciphertext)-1])
	decryptedPayload := ciphertext[:len(ciphertext)-paddingLength]

	return string(decryptedPayload), nil
}

func requestQuestionFromNIDA(nin string) (RQVerificationResult, error) {
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
			</Payload>
			<Signature>%s</Signature>
		</soap:Body>
	</soap:Envelope>`, time.Now().Format(time.RFC3339), "ClientIP", "UserID", "EncryptedCryptoKey", "EncryptedCryptoIV", nin, "Signature")

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

	// Send the request to NIDA (replace URL with actual NIDA API endpoint)
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
