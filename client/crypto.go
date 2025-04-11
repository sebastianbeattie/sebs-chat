package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func encrypt(messageFile string, config Config) {
	var inputMessage InputMessage

	jsonFile, err := os.Open(messageFile)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return
	}
	json.Unmarshal(byteValue, &inputMessage)

	senderPriv, err := loadKeyFromFile(config.SelfKeyConfig.Private)
	if err != nil {
		fmt.Println("Error loading sender private key:", err)
		return
	}

	symKey := make([]byte, 32)
	rand.Read(symKey)

	ciphertext, nonce, err := encryptSymmetric([]byte(inputMessage.RawText), symKey)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	encryptedKeys := make(map[string]string)
	for _, user := range inputMessage.Recipients {
		pubPath := getUserPublicKey(config.ExternalKeysDir, user)
		pub, err := loadKeyFromFile(pubPath)
		if err != nil {
			fmt.Println("Error loading recipient public key:", err)
			return
		}
		sharedKey, err := deriveSharedKey(senderPriv, pub)
		if err != nil {
			fmt.Println("Error deriving shared key:", err)
			return
		}
		encKey, encNonce, err := encryptSymmetric(symKey, sharedKey)
		if err != nil {
			fmt.Println("Error encrypting symmetric key:", err)
			return
		}
		encryptedKeys[user] = base64.StdEncoding.EncodeToString(append(encNonce, encKey...))
	}

	sig, err := signMessage(ciphertext, config.SelfKeyConfig.SigningPrivate)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	signingPub, err := loadKeyFromFile(config.SelfKeyConfig.SigningPublic)
	if err != nil {
		fmt.Println("Error loading signing public key:", err)
		return
	}

	outputMsg := EncryptedMessage{
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		EncryptedKeys:    encryptedKeys,
		Signature:        base64.StdEncoding.EncodeToString(sig),
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPub),
		Sender:           config.UserID,
	}
	jsonData, err := json.MarshalIndent(outputMsg, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}
	fmt.Println(string(jsonData))
}

func decrypt(jsonInput string, config Config) {
	var msg EncryptedMessage
	jsonFile, err := os.Open(jsonInput)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return
	}
	json.Unmarshal(byteValue, &msg)

	priv, err := loadKeyFromFile(config.SelfKeyConfig.Private)
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	senderPubPath := getUserPublicKey(config.ExternalKeysDir, msg.Sender)
	senderPub, err := loadKeyFromFile(senderPubPath)
	if err != nil {
		fmt.Println("Error loading sender public key:", err)
		return
	}

	sharedKey, err := deriveSharedKey(priv, senderPub)
	if err != nil {
		fmt.Println("Error deriving shared key:", err)
		return
	}

	encKeyFull, err := base64.StdEncoding.DecodeString(msg.EncryptedKeys[config.UserID])
	if err != nil {
		fmt.Println("Error decoding encrypted key:", err)
		return
	}
	encNonce := encKeyFull[:chacha20poly1305.NonceSizeX]
	encKey := encKeyFull[chacha20poly1305.NonceSizeX:]

	symKey, err := decryptSymmetric(encKey, sharedKey, encNonce)
	if err != nil {
		fmt.Println("Error decrypting symmetric key:", err)
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
	if err != nil {
		fmt.Println("Error decoding nonce:", err)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(msg.Ciphertext)
	if err != nil {
		fmt.Println("Error decoding ciphertext:", err)
		return
	}

	sig, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return
	}

	signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
	if err != nil {
		fmt.Println("Error decoding signing public key:", err)
		return
	}

	if !ed25519.Verify(signingPub, ciphertext, sig) {
		fmt.Println("Signature verification failed!")
		return
	}

	plaintext, err := decryptSymmetric(ciphertext, symKey, nonce)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	fmt.Printf("%s: %s\n", msg.Sender, string(plaintext))
}

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
