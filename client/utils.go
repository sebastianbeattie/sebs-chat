package main

import (
	"errors"
	"io/fs"
	"os"
)

func checkRecipientKeysExist(recipients []string, config Config) []string {
	var missing []string
	for _, recipient := range recipients {
		if !keyExists(recipient, config) {
			missing = append(missing, recipient)
		}
	}
	return missing
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
	return "", errors.New("username not found")
}
