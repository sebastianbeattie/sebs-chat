package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func saveKeyToFile(filename string, key []byte) error {
	return os.WriteFile(filename, key, 0600)
}

func loadKeyFromFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func getUserPublicKey(externalKeysDir, userID string) string {
	return fmt.Sprintf("%s/%s/public.key", externalKeysDir, userID)
}

func getAuthToken(config Config) (string, error) {
	authTokenPath := fmt.Sprintf("%s/auth_token", config.Keys.PrivateKeys)
	return readTextFromFile(authTokenPath)
}

func saveTextToFile(filename string, text string) error {
	return os.WriteFile(filename, []byte(text), 0600)
}

func readTextFromFile(filename string) (string, error) {
	fileContents, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(fileContents), nil
}

func readJson[T any](path string) (T, error) {
	var result T

	file, err := os.Open(path)
	if err != nil {
		return result, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return result, fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(bytes, &result); err != nil {
		return result, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return result, nil
}

func writeExternalKey(userId, key string, config Config) error {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("error decoding base64 key: %v", err)
	}
	err = saveKeyToFile(fmt.Sprintf("%s/%s/public.key", config.Keys.ExternalKeys, userId), keyBytes)
	if err != nil {
		return fmt.Errorf("error saving external key: %v", err)
	}
	return nil
}
