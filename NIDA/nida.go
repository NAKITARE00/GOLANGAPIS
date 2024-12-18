package main

import (
	dbase "NIDA/db"
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/smtp"
	"time"
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


func retrieveMerchantDetails(nin string) (Merchant, error) {
	// Retrieve cfg database configuration
	cfg := initCFG()

	db, err := dbase.NewMySQLStorage(cfg)
	if err != nil {
		return Merchant{}, err
	}
	defer db.Close()

	// Query to get merchant details
	query := "SELECT merchant_name, merchant_id, email FROM merchants WHERE nin = ?"
	var name, id, email string
	err = db.QueryRow(query, nin).Scan(&name, &id, &email)
	if err != nil {
		return Merchant{}, err
	}

	return Merchant{FirstName: name, LastName: "LastName", Telephone: "Telephone", NIN: id, Email: email}, nil
}

func emailTrigger(nin string) {
	// Retrieve merchant details
	merchant, err := retrieveMerchantDetails(nin)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate a unique token
	token, err := generateToken()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Store the token with a 10-minute expiration
	storeToken(token, 10*time.Minute)

	// email details
	from := "your-email@example.com"
	password := "your-email-password"
	to := []string{merchant.Email}
	smtpHost := "smtp.example.com"
	smtpPort := "587"

	// Create the link
	link := fmt.Sprintf("https://yourdomain.com/verify?token=%s", token)
	message := []byte(fmt.Sprintf("Subject: Notification\n\nHello %s,\n\nPlease click the link below to verify:\n\n%s\n\nThis link will expire in 10 minutes.", merchant.FirstName, link))

	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Send email
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Email sent successfully to", merchant.Email)
}

func requestQuestionFromNIDA(r *http.Request, nin string) (RQVerificationResult, error) {
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

	// Send the request to NIDA
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
