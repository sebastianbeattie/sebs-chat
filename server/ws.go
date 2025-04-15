package main

import (
	"encoding/json"
	"log"

	"github.com/gofiber/contrib/websocket"
)

func websocketHandler(c *websocket.Conn) {
	var (
		connectionMetadata *ConnectionMetadata
		messageType        int
		messageBytes       []byte
		err                error
	)

	token := c.Query("token")
	if token == "" {
		c.Close()
		return
	}

	defer func() {
		removeConnectionMetadata(token)
		c.Close()
	}()

	connectionMetadata, err = getConnectionMetadata(token)
	if err != nil {
		log.Println("Invalid token:", err)
		return
	}

	connectionMetadata.Connection = c

	for {
		messageType, messageBytes, err = c.ReadMessage()
		if err != nil {
			log.Printf("WebSocket closed for token %s: %v\n", token, err)
			break
		}

		log.Printf("recv: %s", messageBytes)

		messageContainer := &WebSocketMessage{}
		if err = json.Unmarshal(messageBytes, messageContainer); err != nil {
			log.Println("unmarshal error:", err)
			continue
		}

		switch messageContainer.MessageType {
		case "chat-message":

			textMessage := &TextMessageContainer{}
			err := json.Unmarshal([]byte(messageContainer.Message), textMessage)
			if err != nil {
				log.Println("unmarshal error:", err)
				continue
			}

			recipients := getRecipients(textMessage.GroupName)
			for _, recipient := range recipients {
				if err := recipient.Connection.WriteJSON(messageContainer); err != nil {
					log.Printf("write to recipient error: %v\n", err)
				}
			}

			if err = c.WriteMessage(messageType, messageBytes); err != nil {
				log.Printf("echo write error: %v\n", err)
			}
		default:
			log.Printf("unknown message type: %s\n", messageContainer.MessageType)

		}
	}
}
