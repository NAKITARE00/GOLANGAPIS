package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
**************************someb64base64encodedRSAprivatekeydata
-----END RSA PRIVATE KEY-----`

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
********************************publickeydata
-----END PUBLIC KEY-----`

type ResponseCryptoInfo struct {
	EncryptedCryptoKey string `xml:"EncryptedCryptoKey"`
	EncryptedCryptoIV  string `xml:"EncryptedCryptoIV"`
}

func decryptCryptoInfo(cryptoInfo ResponseCryptoInfo) ([]byte, []byte, error) {
	// Decode the base64 encrypted AES key and IV
	encryptedAESKey, err := base64.StdEncoding.DecodeString(cryptoInfo.EncryptedCryptoKey)
	if err != nil {
		return nil, nil, err
	}
	encryptedAESIV, err := base64.StdEncoding.DecodeString(cryptoInfo.EncryptedCryptoIV)
	if err != nil {
		return nil, nil, err
	}

	// Parsing the RSA private key
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

func encryptAESKeyAndIV(aesKey, aesIV []byte) (string, string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", "", fmt.Errorf("failed to parse PEM block containing the public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", "", err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("not an RSA public key")
	}

	encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, aesKey)
	if err != nil {
		return "", "", err
	}
	encryptedAESIV, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, aesIV)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedAESKey), base64.StdEncoding.EncodeToString(encryptedAESIV), nil
}

func encryptPayload(payload string, aesKey, aesIV []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	paddedPayload := pad([]byte(payload), aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(paddedPayload))
	iv := aesIV
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPayload)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func signPayload(payload string, privateKey *rsa.PrivateKey) (string, error) {
	h := sha1.New()
	h.Write([]byte(payload))
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func pad(src []byte, blocksize int) []byte {
	padLen := blocksize - len(src)%blocksize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padding...)
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func verifySignature(payload, signature string, publicKey *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	h := sha1.New()
	h.Write([]byte(payload))
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, sig)
}
