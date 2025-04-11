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

func loginGroup(group string, config Config) {
	authToken, err := readTextFromFile(config.SelfKeyConfig.AuthToken)
	if err != nil {
		fmt.Println("Error reading auth token:", err)
		return
	}
	request := LoginRequest{
		GroupName: group,
		AuthToken: authToken,
	}

	loginResponse, err := login(config, request)
	if err != nil {
		fmt.Println("Error logging in to group:", err)
		return
	}
	fmt.Printf("Created login request for group %s\n", group)
	fmt.Printf("Connect token: %s\n", loginResponse.ConnectToken)

	websocketUrl := websocketUrl(config.ServerConfig, loginResponse.ConnectToken)
	ws, err := connectToWebSocket(websocketUrl)
	if err != nil {
		fmt.Println("Error connecting to websocket:", err)
		return
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
