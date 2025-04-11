package main

import "github.com/gofiber/contrib/websocket"

type Config struct {
	MongoDbConnectionString string `json:"mongoDbConnectionString"`
	ServerPort              string `json:"serverPort"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
}

type CreateUserResponse struct {
	Token string `json:"token"`
}

type CreateGroupRequest struct {
	GroupName       string   `json:"groupName"`
	GroupMembers    []string `json:"groupMembers"`
	DeleteWhenEmpty bool     `json:"deleteWhenEmpty"`
	AuthToken       string   `json:"authToken"`
}

type CreateGroupResponse struct {
	GroupName       string   `json:"groupName"`
	GroupMembers    []string `json:"groupMembers"`
	DeleteWhenEmpty bool     `json:"deleteWhenEmpty"`
	Owner           string   `json:"owner"`
}

type GetGroupRequest struct {
	GroupName string `json:"groupName"`
	AuthToken string `json:"authToken"`
}

type Group struct {
	GroupName       string   `json:"groupName"`
	GroupMembers    []string `json:"groupMembers"`
	DeleteWhenEmpty bool     `json:"deleteWhenEmpty"`
	Owner           string   `json:"owner"`
}

type GetUserMembershipsRequest struct {
	AuthToken string `json:"authToken"`
}

type GetUserMembershipsResponse struct {
	Groups []Group `json:"groups"`
}

type LoginRequest struct {
	GroupName string `json:"groupName"`
	AuthToken string `json:"authToken"`
}

type LoginResponse struct {
	ConnectToken string `json:"connectToken"`
}

type ConnectionRequest struct {
	GroupName    string `json:"groupName"`
	Username     string `json:"userId"`
	ConnectToken string `json:"connectToken"`
	CreationTime int64  `json:"creationTime"`
}

type ConnectionMetadata struct {
	GroupName    string
	Username     string
	Connection   *websocket.Conn
	ConnectToken string
}
