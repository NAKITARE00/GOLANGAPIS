package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	aesKey:= make([]byte, 32)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	rawPayload := "Payload"
	
	decryptPayload()

	req := IRequest{
		Header: RequestHeader{
			Id:          "1234567890",
			TimeStamp:   time.Now(),
			ClientName:  "ClientName",
			UserID:      "UserID",
		},
		Body: RequestBody{
			CryptoInfo: ResponseCryptoInfo{
				EncryptedCryptoKey: "EncryptedCryptoKey",
				EncryptedCryptoIV:  "EncryptedCryptoIV",
			},
			Payload:   "Payload",
			Signature: "Signature",
		},
	}
}
