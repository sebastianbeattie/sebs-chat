package main

type EncryptedMessage struct {
	Ciphertext       string            `json:"ciphertext"`
	Nonce            string            `json:"nonce"`
	EncryptedKeys    map[string]string `json:"encrypted_keys"`
	Signature        string            `json:"signature"`
	SigningPublicKey string            `json:"signing_public_key"`
	Sender           string            `json:"sender"`
}

type InputMessage struct {
	RawText    string   `json:"rawText"`
	Recipients []string `json:"recipients"`
}

type SelfKeyConfig struct {
	Private        string `json:"private"`
	Public         string `json:"public"`
	SigningPrivate string `json:"signingPrivate"`
	SigningPublic  string `json:"signingPublic"`
}

type Config struct {
	UserID          string        `json:"userId"`
	SelfKeyConfig   SelfKeyConfig `json:"selfKeyConfig"`
	ExternalKeysDir string        `json:"externalKeysDir"`
}
