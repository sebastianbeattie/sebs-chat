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
	case "create":
		fmt.Println("Generating keys...")
		createKeypair(config.SelfKeyConfig)
		createSigningKeypair(config.SelfKeyConfig)
	case "encrypt":
		encrypt(args.Input, config)
	case "decrypt":
		decrypt(args.Input, config)
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
