package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func checkRecipientKeysExist(recipients []string, config Config) []string {
	var existingKeys []string
	for _, recipient := range recipients {
		if keyExists(recipient, config) {
			existingKeys = append(existingKeys, recipient)
		}
	}
	return existingKeys
}

func keyExists(recipient string, config Config) bool {
	fileExists, _ := exists(config.Keys.ExternalKeys + "/" + recipient + "/public.key")
	return fileExists
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

func contains(a []string, b string) bool {
	for _, c := range a {
		if c == b {
			return true
		}
	}
	return false
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

func exportPublicKey(config Config, target string) (KeyExchange, error) {
	keyBytes, err := loadKeyFromFile(fmt.Sprintf("%s/public.key", config.Keys.PrivateKeys))
	if err != nil {
		return KeyExchange{}, fmt.Errorf("error loading public key: %v", err)
	}
	keyString := base64.StdEncoding.EncodeToString(keyBytes)
	keyExchangeContainer := KeyExchange{
		KeyFrom: config.UserID,
		KeyTo:   target,
		Key:     keyString,
	}
	return keyExchangeContainer, nil
}

func importPublicKey(keyExchange KeyExchange, config Config) error {
	if keyExchange.KeyFrom == config.UserID {
		return fmt.Errorf("cannot import own public key")
	}
	if keyExchange.KeyTo != config.UserID {
		return fmt.Errorf("key exchange not intended for this user")
	}

	err := writeExternalKey(keyExchange.KeyFrom, keyExchange.Key, config)
	if err != nil {
		return fmt.Errorf("error writing external key: %v", err)
	}
	return nil
}
