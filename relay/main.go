package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/gorilla/websocket"
)

type Config struct {
	BindAddress string `json:"bindAddress"`
	Port        int    `json:"port"`
	MaxUsers    int    `json:"maxUsers"`
}

type ClientMap struct {
	sync.RWMutex
	Sessions map[string]*websocket.Conn
}

var config Config

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // allow all origins (for demo purposes)
	},
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9]{1,32}$`)

// Manage connected clients
var clients = ClientMap{
	Sessions: make(map[string]*websocket.Conn),
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if !usernameRegex.MatchString(username) {
		http.Error(w, "Invalid or missing username. Must be alphanumeric and 1-32 characters.", http.StatusBadRequest)
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
				// Don't log normal close errors
				break
			}
			log.Printf("Read error for '%s': %v\n", username, err)
			break
		}
		log.Printf("Received from '%s': %s\n", username, message)
		// Echo message back
		err = conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			log.Printf("Write error for '%s': %v\n", username, err)
			break
		}
	}
}

// Send a message to a list of users
func sendMessageToUsers(usernames []string, message string) {
	clients.RLock()
	defer clients.RUnlock()
	for _, username := range usernames {
		if conn, ok := clients.Sessions[username]; ok {
			err := conn.WriteMessage(websocket.TextMessage, []byte(message))
			if err != nil {
				log.Printf("Error sending message to '%s': %v\n", username, err)
			} else {
				log.Printf("Sent message to '%s'\n", username)
			}
		} else {
			log.Printf("User '%s' not connected\n", username)
		}
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

func main() {
	err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	http.HandleFunc("/ws", wsHandler)
	address := fmt.Sprintf("%s:%d", config.BindAddress, config.Port)
	log.Printf("WebSocket server starting on %s\n", address)
	err = http.ListenAndServe(address, nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
