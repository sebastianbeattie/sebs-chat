package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
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

func main() {
	configPath := flag.String("config", "config.json", "Path to the config file")
	cmd := flag.String("cmd", "", "Command: create, encrypt, decrypt")
	message := flag.String("input", "", "Path to JSON message to encrypt or decrypt")

	flag.Parse()

	if *cmd == "" {
		fmt.Println("Please provide a command using -cmd flag")
		return
	}

	var config Config

	jsonFile, err := os.Open(*configPath)
	if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}
	json.Unmarshal(byteValue, &config)

	switch *cmd {
	case "create":
		createKeypair(config.SelfKeyConfig)
		createSigningKeypair(config.SelfKeyConfig)
	case "encrypt":
		encrypt(*message, config)
	case "decrypt":
		decrypt(*message, config)
	default:
		fmt.Printf("Unsupported command '%s'\n", *cmd)
	}
}
