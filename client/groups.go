package main

import (
	"fmt"
	"strings"
)

func printGroupInfo(group Group) {
	fmt.Printf("Group Name: %s\n", group.GroupName)
	fmt.Printf("Members: %s\n", strings.Join(group.Members, ", "))
	fmt.Printf("Delete When Empty: %v\n", group.DeleteWhenEmpty)
	fmt.Printf("Owner: %s\n", group.Owner)
}

func createMessageGroup(inputFile string, config Config) (Group, error) {
	authToken, err := getAuthToken(config)
	if err != nil {
		return Group{}, fmt.Errorf("error reading auth token: %v", err)
	}

	request, err := readJson[CreateGroupRequest](inputFile)
	if err != nil {
		return Group{}, fmt.Errorf("error reading input file: %v", err)
	}
	request.AuthToken = authToken

	response, err := createGroup(config, request)
	if err != nil {
		return Group{}, fmt.Errorf("error creating group: %v", err)
	}
	return response, nil
}

func getGroupInfo(groupName string, config Config) (Group, error) {
	authToken, err := getAuthToken(config)
	if err != nil {
		return Group{}, fmt.Errorf("error reading auth token: %v", err)
	}
	request := GetGroupRequest{
		GroupName: groupName,
		AuthToken: authToken,
	}

	group, err := getGroup(config, request)
	if err != nil {
		return Group{}, fmt.Errorf("error getting group info: %v", err)
	}
	return group, nil
}

func getGroupsContainingMember(config Config) ([]Group, error) {
	authToken, err := getAuthToken(config)
	if err != nil {
		return []Group{}, fmt.Errorf("error reading auth token: %v", err)
	}
	request := GetGroupMembershipsRequest{
		AuthToken: authToken,
	}

	groups, err := getGroups(config, request)
	if err != nil {
		return []Group{}, fmt.Errorf("error getting groups: %v", err)
	}

	return groups.Groups, nil
}
