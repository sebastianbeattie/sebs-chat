package main

import (
	"fmt"
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
