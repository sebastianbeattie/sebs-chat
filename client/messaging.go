package main

import (
	"fmt"

	"github.com/fasthttp/websocket"
)

func websocketUrl(serverConfig ServerConfig, temporaryToken string) string {
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

	websocketUrl := websocketUrl(config.ServerConfig, loginResponse.ConnectToken)
	ws, err := connectToWebSocket(websocketUrl)
	if err != nil {
		return fmt.Errorf("error connecting to websocket: %v", err)
	}
	defer ws.Close()
	fmt.Println("Connected to websocket server")

	go listenForMessages(ws)
	go sendMessages(ws)

	// Keep the main function running
	select {}
}

func sendMessages(ws *websocket.Conn) {
	for {
		var message string
		fmt.Print("> ")
		fmt.Scanln(&message)

		err := ws.WriteMessage(websocket.TextMessage, []byte(message))
		if err != nil {
			fmt.Println("Error sending message:", err)
			return
		}
	}
}

func listenForMessages(ws *websocket.Conn) {
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			fmt.Println("Error reading message:", err)
			return
		}
		fmt.Printf("Received message: %s\n", message)
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
