package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/gofiber/contrib/websocket"
)

func websocketHandler(c *websocket.Conn) {
	var (
		connectionMetadata *ConnectionMetadata
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
		_, messageBytes, err = c.ReadMessage()
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
			err := json.Unmarshal(messageContainer.Message, textMessage)
			if err != nil {
				log.Println("unmarshal error:", err)
				continue
			}
			err = broadcastToGroup(textMessage.GroupName, messageContainer, *c)
			if err != nil {
				log.Println("broadcast error:", err)
				continue
			}
		case "join-leave-event":
			event := &JoinLeaveEvent{}
			err := json.Unmarshal(messageContainer.Message, event)
			if err != nil {
				log.Println("unmarshal error:", err)
				continue
			}
			err = broadcastToGroup(event.GroupName, messageContainer, *c)
			if err != nil {
				log.Println("broadcast error:", err)
				continue
			}
		case "key-exchange":
			keyExchange := &KeyExchangeEvent{}
			err := json.Unmarshal(messageContainer.Message, keyExchange)
			if err != nil {
				log.Println("unmarshal error:", err)
				continue
			}
			targetConnection := getUserConnection(keyExchange.KeyTo)
			if targetConnection == nil {
				log.Printf("target user %s not found\n", keyExchange.KeyTo)
				continue
			}
			err = targetConnection.Connection.WriteJSON(messageContainer)
			if err != nil {
				log.Printf("write to target user %s error: %v\n", keyExchange.KeyTo, err)
				continue
			}

		default:
			log.Printf("unknown message type: %s\n", messageContainer.MessageType)
		}
	}
}

func broadcastToGroup(group string, messageContainer *WebSocketMessage, self websocket.Conn) error {
	recipients := getRecipients(group)
	for _, recipient := range recipients {
		if err := recipient.Connection.WriteJSON(messageContainer); err != nil {
			return fmt.Errorf("write to recipient error: %v", err)
		}
	}

	if err := self.WriteJSON(messageContainer); err != nil {
		return fmt.Errorf("echo write error: %v", err)
	}

	return nil
}
