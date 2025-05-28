package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/fasthttp/websocket"
)

func createWebsocketUrl(relay Relay) string {
	url := "ws"
	if relay.UseTls {
		url = "wss"
	}

	url += "://" + relay.Address
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
	ws, err := connectToWebSocket(createWebsocketUrl(config.Relay))
	if err != nil {
		return fmt.Errorf("error connecting to relay websocket: %v", err)
	}

	defer disconnectWebSocket(ws)
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

func sendMessage(ws *websocket.Conn, recipients []string, config Config, message string) error {
	input := InputMessage{
		RawText:    message,
		Recipients: recipients,
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

func filterRecipients(onlineUsers []string, safeList []string) []string {
	recipients := []string{}

	for _, recipient := range onlineUsers {
		if keyExists(recipient, config) {
			recipients = append(recipients, recipient)
		}
	}

	if len(safeList) > 0 {
		recipientCopy := recipients
		recipients = []string{}

		for _, recipient := range recipientCopy {
			if contains(safeList, recipient) {
				recipients = append(recipients, recipient)
			}
		}
	}

	return recipients
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func listUsers() ([]string, error) {
	url := createHttpUrl(config.Relay) + "api/list-users"

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
