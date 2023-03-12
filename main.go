package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	// Generate RSA key pair with 2048-bit key size
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println("private key : ", privateKey)

	// Example message to encrypt and decrypt
	message := []byte("Hello, RSA!")

	// Encrypt message using public key
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&privateKey.PublicKey,
		message,
		[]byte(""),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypt message using private key
	plaintext, err := privateKey.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Plaintext: %s\n", plaintext)
}
