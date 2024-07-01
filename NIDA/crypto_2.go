package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
)

func encryptAESKeyAndIVBytes(cfg *Config, aesKey, aesIV []byte) ([]byte, []byte, error) {
	encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, cfg.MessageSecurityPubKey, aesKey)
	if err != nil {
		return nil, nil, err
	}

	encryptedAESIV, err := rsa.EncryptPKCS1v15(rand.Reader, cfg.MessageSecurityPubKey, aesIV)
	if err != nil {
		return nil, nil, err
	}

	return encryptedAESKey, encryptedAESIV, nil
}

func encryptPayloadBytes(payload []byte, aesKey, aesIV []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	paddedPayload := pad(payload, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(paddedPayload))
	iv := aesIV
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPayload)

	return ciphertext, nil
}

func signPayloadBytes(payload []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := sha1.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func decryptPayloadBytes(ciphertext []byte, aesKey, aesIV []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Use CBC mode
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := aesIV
	ciphertext = ciphertext[aes.BlockSize:]

	// Decrypt the payload
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted payload (assuming PKCS7 padding)
	paddingLength := int(ciphertext[len(ciphertext)-1])
	decryptedPayload := ciphertext[:len(ciphertext)-paddingLength]

	return decryptedPayload, nil
}
