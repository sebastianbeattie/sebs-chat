package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func serverUrl(serverConfig ServerConfig, path string) string {
	url := "http"
	if serverConfig.UseTls {
		url = "https"
	}

	url += "://" + serverConfig.Host

	if serverConfig.Port != 0 {
		url += fmt.Sprintf(":%d", serverConfig.Port)
	}

	url += path
	return url
}

func createGroup(config Config, request CreateGroupRequest) (Group, error) {
	url := serverUrl(config.ServerConfig, "/group/create")

	requestBody, err := json.Marshal(request)
	if err != nil {
		return Group{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return Group{}, fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errorMessage ErrorResponse
		err := json.Unmarshal(body, &errorMessage)
		if err != nil {
			return Group{}, fmt.Errorf("failed to read error response: %w", err)
		}
		return Group{}, fmt.Errorf("error response from server: %s", errorMessage.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Group{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var response Group
	err = json.Unmarshal(body, &response)
	if err != nil {
		return Group{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return response, nil
}

func createUser(config Config, request CreateUserRequest) error {
	url := serverUrl(config.ServerConfig, "/user/register")

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errorMessage ErrorResponse
		err := json.Unmarshal(body, &errorMessage)
		if err != nil {
			return fmt.Errorf("failed to read error response: %w", err)
		}
		return fmt.Errorf("error response from server: %s", errorMessage.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	fmt.Printf("Created user '%s' successfully!\n", request.Username)

	var response CreateUserResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	err = saveTextToFile(fmt.Sprintf("%s/auth_token", config.Keys.PrivateKeys), response.AuthToken)
	if err != nil {
		return fmt.Errorf("failed to save auth token: %w", err)
	}
	return nil
}

func getGroup(config Config, request GetGroupRequest) (Group, error) {
	url := serverUrl(config.ServerConfig, "/group/"+request.GroupName)

	requestBody, err := json.Marshal(request)
	if err != nil {
		return Group{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return Group{}, fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errorMessage ErrorResponse
		err := json.Unmarshal(body, &errorMessage)
		if err != nil {
			return Group{}, fmt.Errorf("failed to read error response: %w", err)
		}
		return Group{}, fmt.Errorf("error response from server: %s", errorMessage.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Group{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var response Group
	err = json.Unmarshal(body, &response)
	if err != nil {
		return Group{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return response, nil
}

func getGroups(config Config, request GetGroupMembershipsRequest) (Groups, error) {
	url := serverUrl(config.ServerConfig, "/user/memberships")

	requestBody, err := json.Marshal(request)
	if err != nil {
		return Groups{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return Groups{}, fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errorMessage ErrorResponse
		err := json.Unmarshal(body, &errorMessage)
		if err != nil {
			return Groups{}, fmt.Errorf("failed to read error response: %w", err)
		}
		return Groups{}, fmt.Errorf("error response from server: %s", errorMessage.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Groups{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var response Groups
	err = json.Unmarshal(body, &response)
	if err != nil {
		return Groups{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return response, nil
}

func login(config Config, request LoginRequest) (LoginResponse, error) {
	url := serverUrl(config.ServerConfig, "/user/login")

	requestBody, err := json.Marshal(request)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errorMessage ErrorResponse
		err := json.Unmarshal(body, &errorMessage)
		if err != nil {
			return LoginResponse{}, fmt.Errorf("failed to read error response, server response was: %s", body)
		}
		return LoginResponse{}, fmt.Errorf("error response from server: %s", errorMessage.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var response LoginResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return response, nil
}
