package main

type EncryptedMessage struct {
	Ciphertext       string            `json:"ciphertext"`
	Nonce            string            `json:"nonce"`
	EncryptedKeys    map[string]string `json:"encryptedKeys"`
	Signature        string            `json:"signature"`
	SigningPublicKey string            `json:"signingPublicKey"`
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
	AuthToken      string `json:"authToken"`
}

type ServerConfig struct {
	Port   int    `json:"port"`
	Host   string `json:"host"`
	UseTls bool   `json:"useTls"`
}

type Config struct {
	UserID          string        `json:"userId"`
	SelfKeyConfig   SelfKeyConfig `json:"selfKeyConfig"`
	ExternalKeysDir string        `json:"externalKeysDir"`
	ServerConfig    ServerConfig  `json:"serverConfig"`
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
