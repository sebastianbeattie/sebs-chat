package main

import (
	"errors"
	"fmt"

	"github.com/fasthttp/websocket"
)

func runCommand(command string, args []string, ws *websocket.Conn) error {
	switch command {
	case "kx":
		if len(args) != 1 {
			return errors.New("usage: /kx <username>")
		}
		username := args[0]
		err := exchangeKey(ws, username)
		if err != nil {
			return fmt.Errorf("error exchanging key: %v", err)
		}
		displayMessage("Key Exchange", fmt.Sprintf("Sent public key to %s", username), "#f0c02b", "#f5e67d")
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	return nil
}
