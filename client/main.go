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
	outputPath string
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
			return writeOutput(base64.StdEncoding.EncodeToString(output))
		},
	}
	encryptCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to input JSON file")
	encryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path to output file (optional)")
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
			output := fmt.Sprintf("%s: %s\n", decryptedMessage.Author, decryptedMessage.RawText)
			return writeOutput(output)
		},
	}
	decryptCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to input file")
	decryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path to output file (optional)")
	decryptCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(decryptCmd)

	exportCmd := &cobra.Command{
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
			return writeOutput(base64.StdEncoding.EncodeToString(output))
		},
	}
	exportCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path to output file (optional)")
	rootCmd.AddCommand(exportCmd)

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
	importCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path to output file (optional)")
	importCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(importCmd)

	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to a relay",
		RunE: func(cmd *cobra.Command, args []string) error {
			return connectToRelay()
		},
	}
	rootCmd.AddCommand(connectCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeOutput(output string) error {
	if outputPath != "" {
		return os.WriteFile(outputPath, []byte(output), 0644)
	}
	fmt.Println(output)
	return nil
}
