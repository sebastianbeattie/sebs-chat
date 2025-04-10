package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func generateX25519KeyPair() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	_, err := rand.Read(priv)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

func createSigningKeypair(selfKeyConfig SelfKeyConfig) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating Ed25519 keypair:", err)
		return
	}
	saveKeyToFile(selfKeyConfig.SigningPrivate, priv)
	saveKeyToFile(selfKeyConfig.SigningPublic, pub)
	fmt.Println("Ed25519 signing key pair saved")
}

func createKeypair(selfKeyConfig SelfKeyConfig) {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}
	saveKeyToFile(selfKeyConfig.Private, priv)
	saveKeyToFile(selfKeyConfig.Public, pub)
	fmt.Println("X25519 key pair saved")
}

func deriveSharedKey(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}

func encryptSymmetric(message, key []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, message, nil)
	return ciphertext, nonce, nil
}

func decryptSymmetric(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func signMessage(message []byte, privPath string) ([]byte, error) {
	priv, err := loadKeyFromFile(privPath)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, message), nil
}
