package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
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
