package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

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

func checkRecipientKeysExist(recipients []string, config Config) []string {
	var noKeys []string
	for _, recipient := range recipients {
		if !keyExists(recipient, config) {
			noKeys = append(noKeys, recipient)
		}
	}
	return noKeys
}

func keyExists(recipient string, config Config) bool {
	fileExists, _ := exists(config.Keys.ExternalKeys + "/" + recipient + "/public.key")
	return fileExists
}

func listKeys(config Config) ([]string, error) {
	files, err := os.ReadDir(config.Keys.ExternalKeys)
	if err != nil {
		return nil, fmt.Errorf("error reading external keys directory: %v", err)
	}

	var keys []string
	for _, file := range files {
		if file.IsDir() {
			keys = append(keys, file.Name())
		}
	}
	return keys, nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func getUsernameFromHash(hash string, config Config) (string, error) {
	files, err := os.ReadDir(config.Keys.ExternalKeys)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if hashString(file.Name()) == hash {
			return file.Name(), nil
		}
	}
	return "", errors.New("username not found (keys have not been exchanged)")
}

func exportPublicKey(config Config) (KeyExchange, error) {
	keyBytes, err := loadKeyFromFile(fmt.Sprintf("%s/public.key", config.Keys.PrivateKeys))
	if err != nil {
		return KeyExchange{}, fmt.Errorf("error loading public key: %v", err)
	}
	keyString := base64.StdEncoding.EncodeToString(keyBytes)
	keyExchangeContainer := KeyExchange{
		KeyFrom: config.UserID,
		Key:     keyString,
	}
	return keyExchangeContainer, nil
}

func importPublicKey(keyExchange KeyExchange, config Config) error {
	if keyExchange.KeyFrom == config.UserID {
		return fmt.Errorf("cannot import own public key")
	}

	err := writeExternalKey(keyExchange.KeyFrom, keyExchange.Key, config)
	if err != nil {
		return fmt.Errorf("error writing external key: %v", err)
	}
	return nil
}
