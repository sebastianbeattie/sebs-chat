package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alexflint/go-arg"
)

func main() {
	arg.MustParse(&args)

	var config Config

	jsonFile, err := os.Open(args.Config)
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

	if args.Command == "" {
		fmt.Println("No command provided")
		return
	}

	switch args.Command {
	case "keygen":
		fmt.Println("Generating keys...")
		err := createKeypair(config.SelfKeyConfig)
		if err != nil {
			fmt.Println("Error generating key pair:", err)
			return
		}
		fmt.Println("X25519 key pair saved")
		err = createSigningKeypair(config.SelfKeyConfig)
		if err != nil {
			fmt.Println("Error generating signing key pair:", err)
			return
		}
		fmt.Println("Ed25519 signing key pair saved")
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
		fmt.Println(string(encryptedMessageBytes))
	case "decrypt":
		encryptedMessage, err := readJson[EncryptedMessage](args.Input)
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
	case "register":
		fmt.Println("Registering user...")
		request := CreateUserRequest{Username: config.UserID}
		err := createUser(config, request)
		if err != nil {
			fmt.Println("Error creating user:", err)
			return
		}
		fmt.Println("User registered successfully.")
	case "create-group":
		createMessageGroup(args.Input, config)
	case "group-info":
		getGroupInfo(args.Group, config)
	case "login":
		loginGroup(args.Group, config)
		return
	case "list-groups":
		getGroupsContainingMember(config)
		return
	case "leave-group":
		return
	case "delete-group":
		return

	default:
		fmt.Printf("Unsupported command '%s'\n", args.Command)
	}
}
