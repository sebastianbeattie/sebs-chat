package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

	fmt.Println("Connected to websocket server")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go listenForMessages(ctx, ws)
	go sendMessages(ctx, ws)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	cancel()

	fmt.Println("\nDisconnecting from group...")

	err = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		fmt.Println("Error sending close message:", err)
	}

	if err := ws.Close(); err != nil {
		fmt.Printf("Error closing WebSocket: %v\n", err)
	} else {
		fmt.Println("WebSocket closed cleanly.")
	}

	return nil
}

func sendMessages(ctx context.Context, ws *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
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
}

func listenForMessages(ctx context.Context, ws *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := ws.ReadMessage()
			if err != nil {
				if isClosedConnError(err) {
					fmt.Println("Connection closed.")
				} else {
					fmt.Println("Error reading message:", err)
				}
				return
			}
			fmt.Printf("Received message: %s\n", message)
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
