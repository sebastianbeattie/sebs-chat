package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/fasthttp/websocket"
)

var warningsDisplayed []string

func createWebsocketUrl(serverConfig ServerConfig, temporaryToken string) string {
	url := "ws"
	if serverConfig.UseTls {
		url = "wss"
	}

	url += "://" + serverConfig.Host

	if serverConfig.Port != 0 {
		url += fmt.Sprintf(":%d", serverConfig.Port)
	}

	url += "/ws?token=" + temporaryToken
	return url
}

func connectGroup(group string, config Config) error {
	authToken, err := readTextFromFile(config.SelfKeyConfig.AuthToken)
	if err != nil {
		return fmt.Errorf("error reading auth token: %v", err)
	}
	request := LoginRequest{
		GroupName: group,
		AuthToken: authToken,
	}

	loginResponse, err := login(config, request)
	if err != nil {
		return fmt.Errorf("error connecting to group: %v", err)
	}

	fmt.Printf("Created connect request for group %s\n", group)

	websocketUrl := createWebsocketUrl(config.ServerConfig, loginResponse.ConnectToken)
	ws, err := connectToWebSocket(websocketUrl)
	if err != nil {
		return fmt.Errorf("error connecting to websocket: %v", err)
	}

	fmt.Println("Connected to websocket server")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer disconnectWebSocket(ws)

	groupInfo, err := getGroupInfo(group, config)
	if err != nil {
		return fmt.Errorf("error getting group info: %v", err)
	}

	// Runs the UI. If the user exits or the UI closes, disconnect
	go listenForMessages(ctx, cancel, ws, config)
	err = createUi(groupInfo, ws, config)
	if err != nil {
		return fmt.Errorf("error with UI: %v", err)
	}

	// Stop the listener goroutine
	cancel()
	fmt.Println("\nDisconnecting from group...")

	err = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		fmt.Println("Error sending close message:", err)
	}

	return nil
}

func sendMessage(ws *websocket.Conn, group Group, config Config, message string) error {
	filteredRecipients := removeUserIdFromRecipientList(group.Members, config.UserID)
	recipientsWithoutKeys := checkRecipientKeysExist(filteredRecipients, config)

	for _, recipient := range recipientsWithoutKeys {
		if !contains(warningsDisplayed, recipient) {
			warningsDisplayed = append(warningsDisplayed, recipient)
			displayWarning(fmt.Sprintf("Couldn't find the public key for %s - they will not receive your messages until this is resolved", recipient))
		}
	}

	for _, recipient := range recipientsWithoutKeys {
		filteredRecipients = removeUserIdFromRecipientList(filteredRecipients, recipient)
	}

	if len(filteredRecipients) == 0 {
		return nil
	}

	inputMessage := InputMessage{
		RawText:    message,
		Recipients: filteredRecipients,
	}

	encryptedMessage, err := encrypt(inputMessage, config)
	if err != nil {
		return fmt.Errorf("error encrypting message: %v", err)
	}

	outgoingMessage := EncryptedMessageContainer{
		GroupName: group.GroupName,
		Message:   encryptedMessage,
	}

	outgoingMessageBytes, err := json.Marshal(outgoingMessage)
	if err != nil {
		return fmt.Errorf("error marshalling outgoing message: %v", err)
	}

	err = ws.WriteMessage(websocket.TextMessage, outgoingMessageBytes)
	if err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	return nil
}

func removeUserIdFromRecipientList(recipients []string, userId string) []string {
	for i, recipient := range recipients {
		if recipient == userId {
			return append(recipients[:i], recipients[i+1:]...)
		}
	}
	return recipients
}

func listenForMessages(ctx context.Context, cancel context.CancelFunc, ws *websocket.Conn, config Config) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := ws.ReadMessage()
			if err != nil {
				if isClosedConnError(err) {
					fmt.Println("WebSocket connection closing...")
				} else {
					fmt.Println("Error reading from WebSocket:", err)
				}
				cancel() // Trigger shutdown
				return
			}

			var incomingMessage EncryptedMessageContainer
			if err = json.Unmarshal(message, &incomingMessage); err != nil {
				fmt.Printf("Malformed message: %s\nError: %v\n", string(message), err)
				continue
			}

			if incomingMessage.Message.Sender == config.UserID {
				continue
			}

			decryptedMessage, err := decrypt(incomingMessage.Message, config)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				continue
			}

			displayMessage(decryptedMessage.Author, decryptedMessage.RawText, "#de8b04", "#ffffff")
		}
	}
}

func connectToWebSocket(url string) (*websocket.Conn, error) {
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to websocket: %w", err)
	}
	return conn, nil
}

func isClosedConnError(err error) bool {
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		if strings.Contains(netErr.Err.Error(), "use of closed network connection") {
			return true
		}
	}
	return false
}

func disconnectWebSocket(ws *websocket.Conn) {
	_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err := ws.Close(); err != nil {
		fmt.Printf("Error closing WebSocket: %v\n", err)
	} else {
		fmt.Println("WebSocket closed cleanly.")
	}
}
