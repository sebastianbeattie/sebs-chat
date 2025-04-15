package main

import "encoding/json"

type EncryptedMessage struct {
	Ciphertext       string            `json:"ciphertext"`
	Verify           string            `json:"verify"`
	EncryptedKeys    map[string]string `json:"encryptedKeys"`
	Signature        string            `json:"signature"`
	SigningPublicKey string            `json:"signingPublicKey"`
	Sender           string            `json:"sender"`
}

type InputMessage struct {
	RawText    string   `json:"rawText"`
	Recipients []string `json:"recipients"`
}

type KeyConfig struct {
	PrivateKeys  string `json:"privateKeysDir"`
	ExternalKeys string `json:"externalKeysDir"`
}

type ServerConfig struct {
	Port   int    `json:"port"`
	Host   string `json:"host"`
	UseTls bool   `json:"useTls"`
}

type Config struct {
	UserID       string       `json:"userId"`
	Keys         KeyConfig    `json:"keyConfig"`
	ServerConfig ServerConfig `json:"serverConfig"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
}

type CreateUserResponse struct {
	AuthToken string `json:"token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type CreateGroupRequest struct {
	GroupName       string   `json:"groupName"`
	Members         []string `json:"groupMembers"`
	DeleteWhenEmpty bool     `json:"deleteWhenEmpty"`
	AuthToken       string   `json:"authToken"`
}

type Group struct {
	GroupName       string   `json:"groupName"`
	Members         []string `json:"groupMembers"`
	DeleteWhenEmpty bool     `json:"deleteWhenEmpty"`
	Owner           string   `json:"owner"`
}

type Groups struct {
	Groups []Group `json:"groups"`
}

type GetGroupRequest struct {
	GroupName string `json:"groupName"`
	AuthToken string `json:"authToken"`
}

type GetGroupMembershipsRequest struct {
	AuthToken string `json:"authToken"`
}

type LoginRequest struct {
	AuthToken string `json:"authToken"`
	GroupName string `json:"groupName"`
}

type LoginResponse struct {
	ConnectToken string `json:"connectToken"`
}

type DecryptedMessage struct {
	RawText string `json:"rawText"`
	Author  string `json:"author"`
}

type EncryptedMessageContainer struct {
	GroupName string           `json:"groupName"`
	Message   EncryptedMessage `json:"message"`
}

type WebSocketMessage struct {
	MessageType string          `json:"type"`
	Message     json.RawMessage `json:"message"`
}

type JoinLeaveEventContainer struct {
	EventType string `json:"eventType"`
	GroupName string `json:"groupName"`
	UserHash  string `json:"user"`
}
