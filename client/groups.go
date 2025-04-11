package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func printGroupInfo(group Group) {
	fmt.Printf("Group Name: %s\n", group.GroupName)
	fmt.Printf("Members: %s\n", strings.Join(group.Members, ", "))
	fmt.Printf("Delete When Empty: %v\n", group.DeleteWhenEmpty)
	fmt.Printf("Owner: %s\n", group.Owner)
}

func createMessageGroup(inputFile string, config Config) {
	authToken, err := readTextFromFile(config.SelfKeyConfig.AuthToken)
	if err != nil {
		fmt.Println("Error reading auth token:", err)
		return
	}
	jsonFile, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return
	}
	var request CreateGroupRequest
	json.Unmarshal(byteValue, &request)
	request.AuthToken = authToken

	response, err := createGroup(config, request)
	if err != nil {
		fmt.Println("Error creating group:", err)
		return
	}
	printGroupInfo(response)
}

func getGroupInfo(groupName string, config Config) {
	authToken, err := readTextFromFile(config.SelfKeyConfig.AuthToken)
	if err != nil {
		fmt.Println("Error reading auth token:", err)
		return
	}
	request := GetGroupRequest{
		GroupName: groupName,
		AuthToken: authToken,
	}

	group, err := getGroup(config, request)
	if err != nil {
		fmt.Println("Error getting group info:", err)
		return
	}
	printGroupInfo(group)
}

func getGroupsContainingMember(config Config) {
	authToken, err := readTextFromFile(config.SelfKeyConfig.AuthToken)
	if err != nil {
		fmt.Println("Error reading auth token:", err)
		return
	}
	request := GetGroupMembershipsRequest{
		AuthToken: authToken,
	}

	groups, err := getGroups(config, request)
	if err != nil {
		fmt.Println("Error getting groups:", err)
		return
	}
	for _, group := range groups.Groups {
		fmt.Println("----------------------")
		printGroupInfo(group)
	}
	fmt.Println("----------------------")
	fmt.Println("Total groups:", len(groups.Groups))
	fmt.Println("----------------------")
}
