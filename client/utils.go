package main

import (
	"errors"
	"io/fs"
	"os"
)

func checkRecipientKeysExist(recipients []string, config Config) []string {
	missing := []string{}
	for _, recipient := range recipients {
		if !keyExists(recipient, config) {
			missing = append(missing, recipient)
		}
	}
	return missing
}

func keyExists(recipient string, config Config) bool {
	fileExists, _ := exists(config.ExternalKeysDir + "/" + recipient + "/public.key")
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
