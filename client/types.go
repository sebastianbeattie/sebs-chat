package main

type MessageObject struct {
	Type     string  `json:"type"`
	Content  *string `json:"content,omitempty"`
	FilePath *string `json:"filePath,omitempty"`
}

type EncryptedMessageObject struct {
	Type      string  `json:"type"`
	Content   string  `json:"content"`
	FileName  *string `json:"fileName,omitempty"`
	Verify    string  `json:"verify"`
	Signature string  `json:"signature"`
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

type Config struct {
	UserID    string    `json:"userId"`
	Keys      KeyConfig `json:"keyConfig"`
	FileStore string    `json:"fileStore"`
}

type DecryptedMessage struct {
	Objects []MessageObject `json:"object"`
	Author  string          `json:"author"`
}

type KeyExchange struct {
	KeyFrom string `json:"keyFrom"`
	Key     string `json:"key"`
}
