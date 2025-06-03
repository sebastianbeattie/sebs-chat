package main

type MessageObject struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

type EncryptedMessageObject struct {
	Type      string `json:"type"`
	Content   string `json:"content"`
	Verify    string `json:"verify"`
	Signature string `json:"signature"`
}

type EncryptedMessage struct {
	Objects          []EncryptedMessageObject `json:"objects"`
	EncryptedKeys    map[string]string        `json:"encryptedKeys"`
	SigningPublicKey string                   `json:"signingPublicKey"`
	Sender           string                   `json:"sender"`
}

type InputMessage struct {
	Objects    []MessageObject `json:"objects"`
	Recipients []string        `json:"recipients"`
}

type KeyConfig struct {
	PrivateKeys  string `json:"privateKeysDir"`
	ExternalKeys string `json:"externalKeysDir"`
}

type Relay struct {
	Address  string   `json:"address"`
	SafeList []string `json:"safeList"`
	UseTls   bool     `json:"useTls"`
}

type Config struct {
	UserID string    `json:"userId"`
	Keys   KeyConfig `json:"keyConfig"`
	Relay  Relay     `json:"relay"`
}

type DecryptedMessage struct {
	Objects []MessageObject `json:"object"`
	Author  string          `json:"author"`
}

type KeyExchange struct {
	KeyFrom string `json:"keyFrom"`
	Key     string `json:"key"`
}

// Relay-specific structs

type RelayTransport struct {
	Type    string `json:"t"`
	Payload string `json:"p"`
}

type UserList struct {
	Users []string `json:"users"`
}
