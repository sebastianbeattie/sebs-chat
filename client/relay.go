package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/fasthttp/websocket"
)

func createWebsocketUrl(relay Relay, userId string) string {
	url := "ws"
	if relay.UseTls {
		url = "wss"
	}

	url += "://" + relay.Address + "/relay?user_id=" + hashString(userId)
	return url
}

func createHttpUrl(relay Relay) string {
	url := "http"
	if relay.UseTls {
		url = "https"
	}

	url += "://" + relay.Address
	return url
}

func connectToRelay() error {
	ws, err := connectToWebSocket(createWebsocketUrl(config.Relay, config.UserID))
	if err != nil {
		return fmt.Errorf("error connecting to relay websocket: %v", err)
	}
	defer disconnectWebSocket(ws)

	fmt.Println("Connected as", config.UserID)

	// Goroutine for sending messages
	go func() {
		for {
			var message string
			fmt.Print("> ")
			_, err := fmt.Scanln(&message)
			if err != nil {
				fmt.Printf("Error reading input: %v\n", err)
				continue
			}
			if message == "" {
				continue
			}
			if err := sendMessage(ws, config, message); err != nil {
				fmt.Printf("Error sending message: %v\n", err)
			}
		}
	}()

	// Main goroutine listens for incoming messages
	for {
		var relayMsg RelayTransport
		err := ws.ReadJSON(&relayMsg)
		if err != nil {
			fmt.Printf("Error reading message: %v\n", err)
			break
		}

		switch relayMsg.Type {
		case "msg":
			username, message, err := handleIncomingMessage(relayMsg)
			if err != nil {
				fmt.Printf("Error handling incoming message: %v\n", err)
			}
			fmt.Printf("%s: %s\n", username, message)
		default:
			fmt.Printf("Unknown message type '%s' received\n", relayMsg.Type)
			continue
		}
	}

	return nil
}

func handleIncomingMessage(relayMsg RelayTransport) (string, string, error) {
	payload, err := base64.StdEncoding.DecodeString(relayMsg.Payload)
	if err != nil {
		return "", "", fmt.Errorf("error decoding payload: %v", err)
	}

	var encMsg EncryptedMessage
	err = json.Unmarshal(payload, &encMsg)
	if err != nil {
		return "", "", fmt.Errorf("error unmarshalling encrypted message: %v", err)
	}

	decryptedMsg, err := decrypt(encMsg, config)
	if err != nil {
		return "", "", fmt.Errorf("error decrypting message: %v", err)
	}

	return decryptedMsg.Author, decryptedMsg.RawText, nil
}

func connectToWebSocket(url string) (*websocket.Conn, error) {
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to websocket: %w", err)
	}
	return conn, nil
}

func sendMessage(ws *websocket.Conn, config Config, message string) error {
	onlineUsers, err := listUsers()
	if err != nil {
		return fmt.Errorf("error listing users: %v", err)
	}

	filteredRecipients, err := filterRecipients(onlineUsers, config.Relay.SafeList)
	if err != nil {
		return fmt.Errorf("error determining recipients: %v", err)
	}

	input := InputMessage{
		RawText:    message,
		Recipients: filteredRecipients,
	}

	enc, err := encrypt(input, config)
	if err != nil {
		return fmt.Errorf("error encrypting message: %v", err)
	}

	output, err := json.Marshal(enc)
	if err != nil {
		return fmt.Errorf("error marshalling encrypted message: %v", err)
	}

	outputBase64 := base64.StdEncoding.EncodeToString(output)
	relayMessage := RelayTransport{
		Type:    "msg",
		Payload: outputBase64,
	}

	err = ws.WriteJSON(relayMessage)
	if err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	return nil
}

func disconnectWebSocket(ws *websocket.Conn) {
	_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err := ws.Close(); err != nil {
		fmt.Printf("Error closing WebSocket: %v\n", err)
	} else {
		fmt.Println("WebSocket closed cleanly.")
	}
}

func filterRecipients(onlineUsers []string, safeList []string) ([]string, error) {
	recipients := []string{}

	usersWithKeys, err := listKeys(config)
	if err != nil {
		return []string{}, fmt.Errorf("error listing keys: %v", err)
	}

	// Remove our own hashed user ID from the list of online users
	ourHashedID := hashString(config.UserID)
	filteredOnlineUsers := []string{}
	for _, userID := range onlineUsers {
		if userID != ourHashedID {
			filteredOnlineUsers = append(filteredOnlineUsers, userID)
		}
	}

	if len(filteredOnlineUsers) == 0 {
		return []string{}, fmt.Errorf("no online users found")
	}

	// Create initial list of recipients based on online users and keys we have available
	for _, recipient := range filteredOnlineUsers {
		for _, userWithKey := range usersWithKeys {
			if hashString(userWithKey) == recipient {
				recipients = append(recipients, userWithKey) // Use the unhashed username for recipients
				break
			}
		}
	}

	if len(recipients) == 0 {
		return []string{}, fmt.Errorf("no recipients found - either no users are online or you have no keys for the online users")
	}

	// If specified, filter recipients again by safe list
	if len(safeList) > 0 {
		recipientCopy := recipients
		recipients = []string{}

		for _, recipient := range recipientCopy {
			for _, safeUser := range safeList {
				if safeUser == recipient {
					recipients = append(recipients, recipient)
					break
				}
			}
		}
	}

	if len(recipients) == 0 {
		return []string{}, fmt.Errorf("no recipients found - either no users are online, you have no keys for the online users or none of the users in your safe list are online")
	}

	return recipients, nil
}

func listUsers() ([]string, error) {
	url := createHttpUrl(config.Relay) + "/api/list-users"
	resp, err := http.Get(url)
	if err != nil {
		return []string{}, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}, fmt.Errorf("error reading response from relay: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return []string{}, fmt.Errorf("unexpected code %d from server: %s", resp.StatusCode, string(body))
	}

	var response UserList
	err = json.Unmarshal(body, &response)
	if err != nil {
		return []string{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return response.Users, nil
}
