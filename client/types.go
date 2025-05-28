package main

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
	RawText string `json:"rawText"`
	Author  string `json:"author"`
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
