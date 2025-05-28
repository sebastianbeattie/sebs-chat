package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/websocket"
)

type Config struct {
	BindAddress string `json:"bindAddress"`
	Port        int    `json:"port"`
	MaxUsers    int    `json:"maxUsers"`
}

type UserList struct {
	Users []string `json:"users"`
}

type RelayTransport struct {
	Type    string `json:"t"`
	Payload string `json:"p"`
}

type ClientMap struct {
	sync.RWMutex
	Sessions map[string]*websocket.Conn
}

var config Config

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // allow all origins
	},
}

// Manage connected clients
var clients = ClientMap{
	Sessions: make(map[string]*websocket.Conn),
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user_id")
	if username == "" {
		http.Error(w, "Missing user_id.", http.StatusBadRequest)
		return
	}

	clients.Lock()
	if len(clients.Sessions) >= config.MaxUsers {
		clients.Unlock()
		http.Error(w, "Maximum number of users reached.", http.StatusServiceUnavailable)
		return
	}
	clients.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	clients.Lock()
	clients.Sessions[username] = conn
	clients.Unlock()
	defer func() {
		clients.Lock()
		delete(clients.Sessions, username)
		clients.Unlock()
		log.Printf("User '%s' disconnected.\n", username)
	}()

	log.Printf("User '%s' connected.\n", username)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				break
			}
			log.Printf("Read error for '%s': %v\n", username, err)
			break
		}

		transport := RelayTransport{}
		err = json.Unmarshal(message, &transport)
		if err != nil {
			log.Printf("Error unmarshalling message from '%s': %v\n", username, err)
			continue
		}

		log.Printf("Received %s from %s\n", transport.Type, username)

		switch transport.Type {
		case "msg":
			forwardEncryptedMessage(message, username)
		default:
			log.Printf("Unknown message type '%s' from '%s'\n", transport.Type, username)
			continue
		}
	}
}

func forwardEncryptedMessage(message []byte, author string) {
	clients.RLock()
	defer clients.RUnlock()
	for userID, conn := range clients.Sessions {
		// Skip the author of the message
		if userID == author {
			continue
		}

		err := conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			log.Printf("Error sending message to '%s': %v\n", userID, err)
			continue
		}
		log.Printf("Forwarded message to '%s'\n", userID)
	}
}

func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	return decoder.Decode(&config)
}

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	clients.RLock()
	userIDs := make([]string, 0, len(clients.Sessions))
	for userID := range clients.Sessions {
		userIDs = append(userIDs, userID)
	}
	clients.RUnlock()

	userList := UserList{Users: userIDs}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userList)
}

func main() {
	err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	http.HandleFunc("/api/list-users", listUsersHandler)
	http.HandleFunc("/relay", wsHandler)

	address := fmt.Sprintf("%s:%d", config.BindAddress, config.Port)
	log.Printf("WebSocket server starting on %s\n", address)
	err = http.ListenAndServe(address, nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
