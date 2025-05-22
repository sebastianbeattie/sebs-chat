package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alexflint/go-arg"
)

var config Config

func generateAllKeys(config Config) error {
	fmt.Println("Generating keys...")
	err := createKeypair(config.Keys.PrivateKeys)
	if err != nil {
		return fmt.Errorf("error generating key pair: %v", err)
	}
	fmt.Println("X25519 key pair saved")
	err = createSigningKeypair(config.Keys.PrivateKeys)
	if err != nil {
		return fmt.Errorf("error generating signing key pair: %v", err)
	}
	fmt.Println("Ed25519 signing key pair saved")
	return nil
}

func main() {
	arg.MustParse(&args)

	jsonFile, err := os.Open(args.Config)
	if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer func(jsonFile *os.File) {
		err := jsonFile.Close()
		if err != nil {
			fmt.Println("Error closing config file:", err)
		}
	}(jsonFile)
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		fmt.Println("Error unmarshalling config file:", err)
		return
	}

	if args.Command == "" {
		fmt.Println("No command provided")
		return
	}

	createKeyDirsIfNotExist(args.Command != "keygen")

	switch args.Command {
	case "keygen":
		err := generateAllKeys(config)
		if err != nil {
			fmt.Println("Error generating keys:", err)
			return
		}
	case "encrypt":
		inputMessage, err := readJson[InputMessage](args.Input)
		if err != nil {
			fmt.Println("Error reading input message:", err)
			return
		}
		encryptedMessage, err := encrypt(inputMessage, config)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}
		encryptedMessageBytes, err := json.MarshalIndent(encryptedMessage, "", "   ")
		if err != nil {
			fmt.Println("Error marshalling encrypted message:", err)
			return
		}
		fmt.Println(base64.StdEncoding.EncodeToString(encryptedMessageBytes))
	case "decrypt":
		encryptedMessage, err := readBase64File[EncryptedMessage](args.Input)
		if err != nil {
			fmt.Println("Error reading input message:", err)
			return
		}
		decryptedMessage, err := decrypt(encryptedMessage, config)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return
		}
		fmt.Printf("%s: %s\n", decryptedMessage.Author, decryptedMessage.RawText)
	case "export-key":
		KeyExchange, err := exportPublicKey(config, args.Recipient)
		if err != nil {
			fmt.Println("Error exporting public key:", err)
			return
		}
		keyExchangeBytes, err := json.MarshalIndent(KeyExchange, "", "   ")
		if err != nil {
			fmt.Println("Error marshalling key exchange:", err)
			return
		}
		fmt.Println(base64.StdEncoding.EncodeToString(keyExchangeBytes))
		return
	case "import-key":
		keyExchange, err := readBase64File[KeyExchange](args.Input)
		if err != nil {
			fmt.Println("Error reading key exchange:", err)
			return
		}
		err = importPublicKey(keyExchange, config)
		if err != nil {
			fmt.Println("Error importing public key:", err)
			return
		}
		fmt.Printf("Public key imported from %s successfully\n", keyExchange.KeyFrom)
		return

	default:
		fmt.Printf("Unsupported command '%s'\n", args.Command)
		return
	}
}

func createKeyDirsIfNotExist(createKeys bool) {
	if _, err := os.Stat(config.Keys.PrivateKeys); os.IsNotExist(err) {
		err = os.MkdirAll(config.Keys.PrivateKeys, os.ModePerm)
		if err != nil {
			fmt.Println("Error creating private keys directory:", err)
			return
		}
		fmt.Println("Created private keys directory:", config.Keys.PrivateKeys)
	}

	if _, err := os.Stat(config.Keys.ExternalKeys); os.IsNotExist(err) {
		err = os.MkdirAll(config.Keys.ExternalKeys, os.ModePerm)
		if err != nil {
			fmt.Println("Error creating external keys directory:", err)
			return
		}
		fmt.Println("Created external keys directory:", config.Keys.ExternalKeys)
	}

	privateKeysDirEntries, err := os.ReadDir(config.Keys.PrivateKeys)
	if err != nil {
		fmt.Println("Error reading private keys directory:", err)
		return
	}
	if len(privateKeysDirEntries) == 0 && createKeys {
		fmt.Println("Private keys directory is empty, generating keys...")
		err = generateAllKeys(config)
		if err != nil {
			fmt.Println("Error generating keys:", err)
			return
		}
	}
}
