package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Config *Config
}

type verifyRequest struct {
	MerchantID uint64 `json:"merchant_id"`
}

func (h *Handlers) verify(c *gin.Context) {
	var request verifyRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Query db using merchant id
	nin, err := queryNin(request.MerchantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Request the first question from NIDA
	err = requestQuestionFromNIDA1(h.Config, nin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send the question back to the client
	c.JSON(http.StatusOK, gin.H{"question": nil})
}

func queryNin(_ uint64) (string, error) {
	return "NIN", nil
}

type SoapHeader struct {
	Id             string    `xml:"Id"`
	Timestamp      time.Time `xml:"TimeStamp"`
	ClientNameOrIP string    `xml:"ClientNameorIP"`
	UserID         string    `xml:"UserID"`
}

type EncodedBytes []byte

func (a *EncodedBytes) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}

	bs, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	*a = bs

	return nil
}

func (eb EncodedBytes) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	s := base64.StdEncoding.EncodeToString(eb)
	return e.EncodeElement(s, start)
}

type SoapCryptoInfo struct {
	EncryptedCryptoKey EncodedBytes `xml:"EncryptedCryptoKey"`
	EncryptedCryptoIV  EncodedBytes `xml:"EncryptedCryptoIV"`
}

type SoapBody struct {
	CryptoInfo SoapCryptoInfo `xml:"CryptoInfo"`
	Payload    EncodedBytes   `xml:"Payload"`
	Signature  EncodedBytes   `xml:"Signature"`
}

type SoapRequest struct {
	Header  SoapHeader `xml:"soap:Header"`
	Body    SoapBody   `xml:"soap:Body"`
	XMLName xml.Name   `xml:"soap:Envelope"`
}

type SoapResponse struct {
	Header  SoapHeader `xml:"Header"`
	Body    SoapBody   `xml:"Body"`
	XMLName xml.Name   `xml:"Envelope"`
}

func (sr SoapResponse) Payload(cfg *Config) ([]byte, error) {
	hasher := sha1.New()
	hasher.Write(sr.Body.Payload)
	if err := rsa.VerifyPKCS1v15(cfg.MessageSecurityPubKey, crypto.SHA1, hasher.Sum(nil), sr.Body.Signature); err != nil {
		return nil, err
	}

	aesKey, err := rsa.DecryptPKCS1v15(nil, cfg.StakeholderPrivKey, sr.Body.CryptoInfo.EncryptedCryptoKey)
	if err != nil {
		return nil, err
	}

	aesIV, err := rsa.DecryptPKCS1v15(nil, cfg.StakeholderPrivKey, sr.Body.CryptoInfo.EncryptedCryptoIV)
	if err != nil {
		return nil, err
	}

	return decryptPayloadBytes(sr.Body.Payload, aesKey, aesIV)
}

func generateAESKeyAndIV() ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

type QuestionPayload struct {
	NIN string `xml:"NIN"`
}

func requestQuestionFromNIDA1(cfg *Config, nin string) error {
	aesKey, aesIV, err := generateAESKeyAndIV()
	if err != nil {
		return err
	}

	payload, err := xml.Marshal(QuestionPayload{NIN: nin})
	if err != nil {
		return err
	}

	encryptedPayload, err := encryptPayloadBytes(payload, aesKey, aesIV)
	if err != nil {
		return err
	}

	encryptedPayloadSignature, err := signPayloadBytes(encryptedPayload, cfg.StakeholderPrivKey)
	if err != nil {
		return err
	}

	encryptedAESKey, encryptedAESIV, err := encryptAESKeyAndIVBytes(cfg, aesKey, aesIV)
	if err != nil {
		return err
	}

	now := time.Now()
	req := SoapRequest{
		Header: SoapHeader{
			Id:             strconv.FormatInt(now.UnixNano(), 10),
			Timestamp:      now,
			ClientNameOrIP: "test",
			UserID:         cfg.UserID,
		},
		Body: SoapBody{
			CryptoInfo: SoapCryptoInfo{
				EncryptedCryptoKey: encryptedAESKey,
				EncryptedCryptoIV:  encryptedAESIV,
			},
			Payload:   encryptedPayload,
			Signature: encryptedPayloadSignature,
		},
	}

	requestPayload, err := xml.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println("REQUEST", string(requestPayload))

	// NIDA API endpoint
	resp, err := http.Post(cfg.NidaURL, "text/xml", bytes.NewBuffer(requestPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Parse the response
	var responseEnvelope SoapResponse
	buf := &bytes.Buffer{}
	if err := xml.NewDecoder(io.TeeReader(resp.Body, buf)).Decode(&responseEnvelope); err != nil {
		fmt.Println("RESPONSE", buf.String())
		return err
	}

	fmt.Println("RESPONSE", buf.String())
	rp, err := responseEnvelope.Payload(cfg)
	fmt.Println("RESPONSE Payload", rp, err)

	return nil
}
