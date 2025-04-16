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
	authToken, err := getAuthToken(config)
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

	sendJoinLeaveMessage(ws, group, config, "join")

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

	sendJoinLeaveMessage(ws, group, config, "leave")
	err = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		fmt.Println("Error sending close message:", err)
	}

	return nil
}

func sendJoinLeaveMessage(ws *websocket.Conn, group string, config Config, eventType string) {
	joinLeaveEventContainer := JoinLeaveEventContainer{
		GroupName: group,
		EventType: eventType,
		UserHash:  hashString(config.UserID),
	}
	joinLeaveEventBytes, err := json.Marshal(joinLeaveEventContainer)
	if err != nil {
		displayError(fmt.Sprintf("error marshalling join/leave event: %v", err))
		return
	}
	outgoingMessage := WebSocketMessage{
		MessageType: "join-leave-event",
		Message:     joinLeaveEventBytes,
	}
	outgoingMessageBytes, err := json.Marshal(outgoingMessage)
	if err != nil {
		displayError(fmt.Sprintf("error marshalling outgoing message: %v", err))
		return
	}
	err = ws.WriteMessage(websocket.TextMessage, outgoingMessageBytes)
	if err != nil {
		displayError(fmt.Sprintf("error sending join/leave message: %v", err))
		return
	}
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

	encryptedMessageContainer := EncryptedMessageContainer{
		GroupName: group.GroupName,
		Message:   encryptedMessage,
	}
	encryptedMessageBytes, err := json.Marshal(encryptedMessageContainer)
	if err != nil {
		return fmt.Errorf("error marshalling encrypted message: %v", err)
	}

	outgoingMessage := WebSocketMessage{
		MessageType: "chat-message",
		Message:     encryptedMessageBytes,
	}

	err = ws.WriteJSON(outgoingMessage)
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

			messageContainer := &WebSocketMessage{}
			if err = json.Unmarshal(message, &messageContainer); err != nil {
				displayError(fmt.Sprintf("Malformed message: %s\nError: %v\n", string(message), err))
				continue
			}

			switch messageContainer.MessageType {
			case "chat-message":
				incomingMessage := &EncryptedMessageContainer{}
				if err = json.Unmarshal(messageContainer.Message, incomingMessage); err != nil {
					displayError(fmt.Sprintf("Malformed chat message: %s\nError: %v\n", string(message), err))
					continue
				}

				if incomingMessage.Message.Sender == hashString(config.UserID) {
					continue
				}

				decryptedMessage, err := decrypt(incomingMessage.Message, config)
				if err != nil {
					displayError(fmt.Sprintf("Error decrypting message: %v", err))
					continue
				}

				displayMessage(decryptedMessage.Author, decryptedMessage.RawText, "#de8b04", "#ffffff")
			case "join-leave-event":
				joinLeaveEvent := &JoinLeaveEventContainer{}
				if err = json.Unmarshal(messageContainer.Message, joinLeaveEvent); err != nil {
					displayError(fmt.Sprintf("Malformed join/leave event: %s\nError: %v\n", string(message), err))
					continue
				}
				if joinLeaveEvent.UserHash == hashString(config.UserID) {
					continue
				}

				username, err := getUsernameFromHash(joinLeaveEvent.UserHash, config)
				if err != nil {
					username = joinLeaveEvent.UserHash
					displayError(fmt.Sprintf("Error getting username: %v", err))
				}
				if joinLeaveEvent.EventType == "join" {
					displayMessage("Member Joined", fmt.Sprintf("%s joined the chat", username), "#4287f5", "#679df5")
				} else if joinLeaveEvent.EventType == "leave" {
					displayMessage("Member Left", fmt.Sprintf("%s left the chat", username), "#f02b60", "#ed8aa4")
				}

			case "key-exchange":
				keyExchange := &KeyExchange{}
				if err = json.Unmarshal(messageContainer.Message, keyExchange); err != nil {
					displayError(fmt.Sprintf("Malformed key exchange message: %s\nError: %v\n", string(message), err))
					continue
				}

				keyAlreadyExisted := keyExists(keyExchange.KeyFrom, config)
				displayMessage("Key Exchange", fmt.Sprintf("Received public key from %s", keyExchange.KeyFrom), "#f0c02b", "#f5e67d")

				err = importPublicKey(*keyExchange, config)
				if err != nil {
					displayError(fmt.Sprintf("Error importing public key: %v", err))
					continue
				}

				if config.Keys.AutoKeyExchange {
					if keyAlreadyExisted {
						displayMessage("Key Exchange", fmt.Sprintf("Public key for %s already exists, skipping automatic key exchange", keyExchange.KeyFrom), "#f0c02b", "#f5e67d")
						continue
					}

					err := exchangeKey(ws, keyExchange.KeyFrom)
					if err != nil {
						displayError(fmt.Sprintf("Error sending public key: %v", err))
						continue
					}
					displayMessage("Key Exchange", fmt.Sprintf("Sent public key to %s", keyExchange.KeyFrom), "#f0c02b", "#f5e67d")
				} else {
					displayWarning(fmt.Sprintf("Auto key exchange is disabled. Please send your public key manually to %s", keyExchange.KeyFrom))
				}

			default:
				displayError(fmt.Sprintf("Unknown message type: %s\n", messageContainer.MessageType))
			}
		}
	}
}

func exchangeKey(ws *websocket.Conn, target string) error {
	keyExchangeContainer, err := exportPublicKey(config, target)
	if err != nil {
		return fmt.Errorf("error exporting public key: %v", err)
	}
	keyExchangeContainerBytes, err := json.Marshal(keyExchangeContainer)
	if err != nil {
		return fmt.Errorf("error marshalling key exchange container: %v", err)
	}
	outgoingMessage := WebSocketMessage{
		MessageType: "key-exchange",
		Message:     keyExchangeContainerBytes,
	}
	outgoingMessageBytes, err := json.Marshal(outgoingMessage)
	if err != nil {
		return fmt.Errorf("error marshalling outgoing message: %v", err)
	}
	err = ws.WriteMessage(websocket.TextMessage, outgoingMessageBytes)
	if err != nil {
		return fmt.Errorf("error sending key exchange message: %v", err)
	}
	return nil
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
