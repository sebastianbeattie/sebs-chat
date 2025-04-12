package main

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	connectionRequests []ConnectionRequest
	connections        []*ConnectionMetadata
	mu                 sync.Mutex
)

func addConnectionRequest(username, groupID string) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	token, err := createAuthToken(16)
	if err != nil {
		return "", err
	}

	connectionRequests = append(connectionRequests, ConnectionRequest{
		Username:     username,
		GroupName:    groupID,
		ConnectToken: token,
		CreationTime: time.Now().Unix(),
	})
	return token, nil
}

func removeConnectionMetadata(token string) {
	mu.Lock()
	defer mu.Unlock()

	for i, conn := range connections {
		if conn.ConnectToken == token {
			connections = append(connections[:i], connections[i+1:]...)
		}
	}
}

func getConnectionMetadata(token string) (*ConnectionMetadata, error) {
	mu.Lock()
	defer mu.Unlock()

	for _, req := range connectionRequests {
		if req.ConnectToken == token {
			newConn := ConnectionMetadata{
				Username:     req.Username,
				GroupName:    req.GroupName,
				ConnectToken: token,
			}
			removeConnectionRequest(token)
			connections = append(connections, &newConn)
			return &newConn, nil
		}
	}
	return &ConnectionMetadata{}, errors.New("invalid connection token")
}

func validateConnectionToken(token string) bool {
	mu.Lock()
	defer mu.Unlock()

	for _, req := range connectionRequests {
		if req.ConnectToken == token {
			return true
		}
	}
	return false
}

func removeConnectionRequest(token string) {
	for i, req := range connectionRequests {
		if req.ConnectToken == token {
			connectionRequests = append(connectionRequests[:i], connectionRequests[i+1:]...)
			break
		}
	}
}

func monitorConnectionRequests() {
	for {
		time.Sleep(1 * time.Second)
		mu.Lock()
		now := time.Now().Unix()
		filteredRequests := connectionRequests[:0]
		for _, req := range connectionRequests {
			if now-req.CreationTime <= 30 {
				filteredRequests = append(filteredRequests, req)
			}
		}
		connectionRequests = filteredRequests
		mu.Unlock()

		if len(connectionRequests) > 0 || len(connections) > 0 {
			fmt.Println("Active connection requests:", len(connectionRequests))
			fmt.Println("Active connections:", len(connections))
		}
	}
}

func init() {
	go monitorConnectionRequests()
}
