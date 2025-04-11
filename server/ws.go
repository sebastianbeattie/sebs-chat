package main

import (
	"fmt"
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

	defer removeConnectionMetadata(token)

	connectionMetadata, err = getConnectionMetadata(token)
	if err != nil {
		log.Println("Invalid token:", err)
		c.Close()
		return
	}

	connectionMetadata.Connection = c

	for {
		if messageType, messageBytes, err = c.ReadMessage(); err != nil {
			fmt.Println("read error:", err)
			break
		}
		log.Printf("recv: %s", messageBytes)

		if err = c.WriteMessage(messageType, messageBytes); err != nil {
			fmt.Println("write error:", err)
			break
		}
	}
}
