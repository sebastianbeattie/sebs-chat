package main

import (
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
