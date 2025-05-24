package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var (
	config     Config
	configPath string
	inputPath  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sebs-chat",
		Short: "A CLI tool for encryption/decryption and key management",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Load config before any subcommand runs
			file, err := os.Open(configPath)
			if err != nil {
				return fmt.Errorf("error opening config file: %v", err)
			}
			defer file.Close()
			byteValue, err := io.ReadAll(file)
			if err != nil {
				return fmt.Errorf("error reading config file: %v", err)
			}
			err = json.Unmarshal(byteValue, &config)
			if err != nil {
				return fmt.Errorf("error unmarshalling config: %v", err)
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "config.json", "Path to config file")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "keygen",
		Short: "Generate key pairs",
		RunE: func(cmd *cobra.Command, args []string) error {
			createKeyDirsIfNotExist(false)
			return generateAllKeys(config)
		},
	})

	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			createKeyDirsIfNotExist(true)
			inputMessage, err := readJson[InputMessage](inputPath)
			if err != nil {
				return fmt.Errorf("error reading input message: %v", err)
			}
			encryptedMessage, err := encrypt(inputMessage, config)
			if err != nil {
				return fmt.Errorf("error encrypting message: %v", err)
			}
			output, err := json.MarshalIndent(encryptedMessage, "", "   ")
			if err != nil {
				return fmt.Errorf("error marshalling encrypted message: %v", err)
			}
			fmt.Println(base64.StdEncoding.EncodeToString(output))
			return nil
		},
	}
	encryptCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to input JSON file")
	encryptCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(encryptCmd)

	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			createKeyDirsIfNotExist(true)
			encryptedMessage, err := readBase64File[EncryptedMessage](inputPath)
			if err != nil {
				return fmt.Errorf("error reading encrypted message: %v", err)
			}
			decryptedMessage, err := decrypt(encryptedMessage, config)
			if err != nil {
				return fmt.Errorf("error decrypting message: %v", err)
			}
			fmt.Printf("%s: %s\n", decryptedMessage.Author, decryptedMessage.RawText)
			return nil
		},
	}
	decryptCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to input file")
	decryptCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(decryptCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "export-key",
		Short: "Export your public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyExchange, err := exportPublicKey(config)
			if err != nil {
				return fmt.Errorf("error exporting public key: %v", err)
			}
			output, err := json.MarshalIndent(keyExchange, "", "   ")
			if err != nil {
				return fmt.Errorf("error marshalling key exchange: %v", err)
			}
			fmt.Println(base64.StdEncoding.EncodeToString(output))
			return nil
		},
	})

	importCmd := &cobra.Command{
		Use:   "import-key",
		Short: "Import a public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyExchange, err := readBase64File[KeyExchange](inputPath)
			if err != nil {
				return fmt.Errorf("error reading key exchange: %v", err)
			}
			err = importPublicKey(keyExchange, config)
			if err != nil {
				return fmt.Errorf("error importing public key: %v", err)
			}
			fmt.Printf("Public key imported from %s successfully\n", keyExchange.KeyFrom)
			return nil
		},
	}
	importCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to input file")
	importCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(importCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
