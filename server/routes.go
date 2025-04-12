package main

import (
	"github.com/gofiber/fiber/v2"
)

func register(c *fiber.Ctx) error {
	var body CreateUserRequest
	if err := c.BodyParser(&body); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid request body",
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse)
	}

	usersCollection := database.Collection("users")

	var existingUser struct{}
	err := usersCollection.FindOne(mongoContext, map[string]interface{}{
		"username": body.Username,
	}).Decode(&existingUser)

	if err == nil {
		ErrorResponse := ErrorResponse{
			Error: "Username is already taken",
		}
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse)
	}

	authToken, err := createAuthToken(128)

	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to create auth token",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}

	_, err = usersCollection.InsertOne(mongoContext, map[string]interface{}{
		"username": body.Username,
		"token":    authToken,
	})

	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to register user",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}

	CreateUserResponse := CreateUserResponse{
		Token: authToken,
	}
	return c.Status(fiber.StatusOK).JSON(CreateUserResponse)
}

func getGroup(c *fiber.Ctx) error {
	var body GetGroupRequest
	if err := c.BodyParser(&body); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid request body",
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse)
	}
	groupName := c.Params("name")
	groupsCollection := database.Collection("groups")
	var group Group
	err := groupsCollection.FindOne(mongoContext, map[string]interface{}{
		"groupName": groupName,
	}).Decode(&group)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Group not found",
		}
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse)
	}

	username, err := getUsernameByToken(body.AuthToken)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid auth token",
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse)
	}

	if !containsString(group.GroupMembers, username) {
		ErrorResponse := ErrorResponse{
			Error: "Group exists, but you do not have permission to view it",
		}
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse)
	}

	return c.Status(fiber.StatusOK).JSON(group)

}

func createGroup(c *fiber.Ctx) error {
	var body CreateGroupRequest
	if err := c.BodyParser(&body); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid request body",
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse)
	}

	username, error := getUsernameByToken(body.AuthToken)
	if error != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid auth token",
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse)
	}

	var existingGroup struct{}
	groupsCollection := database.Collection("groups")
	err := groupsCollection.FindOne(mongoContext, map[string]interface{}{
		"groupName": body.GroupName,
	}).Decode(&existingGroup)
	if err == nil {
		ErrorResponse := ErrorResponse{
			Error: "Group name is already taken",
		}
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse)
	}

	if !containsString(body.GroupMembers, username) {
		body.GroupMembers = append(body.GroupMembers, username)
	}

	_, err = groupsCollection.InsertOne(mongoContext, map[string]interface{}{
		"groupName":       body.GroupName,
		"groupMembers":    body.GroupMembers,
		"deleteWhenEmpty": body.DeleteWhenEmpty,
		"owner":           username,
	})
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to create group",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}
	CreateGroupResponse := CreateGroupResponse{
		GroupName:       body.GroupName,
		GroupMembers:    body.GroupMembers,
		DeleteWhenEmpty: body.DeleteWhenEmpty,
		Owner:           username,
	}
	return c.Status(fiber.StatusOK).JSON(CreateGroupResponse)

}

func getUserMemberships(c *fiber.Ctx) error {
	var body GetUserMembershipsRequest
	if err := c.BodyParser(&body); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid request body",
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse)
	}

	username, err := getUsernameByToken(body.AuthToken)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid auth token",
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse)
	}

	groupsCollection := database.Collection("groups")
	cursor, err := groupsCollection.Find(mongoContext, map[string]interface{}{
		"groupMembers": username,
	})
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to retrieve groups",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}
	defer cursor.Close(mongoContext)

	var groups []Group
	if err = cursor.All(mongoContext, &groups); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to retrieve groups",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}

	GetUserMembershipsResponse := GetUserMembershipsResponse{
		Groups: groups,
	}
	return c.Status(fiber.StatusOK).JSON(GetUserMembershipsResponse)
}

func login(c *fiber.Ctx) error {
	var body LoginRequest
	if err := c.BodyParser(&body); err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid request body",
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse)
	}

	username, err := getUsernameByToken(body.AuthToken)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Invalid auth token",
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse)
	}

	groupsCollection := database.Collection("groups")
	var group Group
	err = groupsCollection.FindOne(mongoContext, map[string]interface{}{
		"groupName": body.GroupName,
	}).Decode(&group)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Group not found",
		}
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse)
	}

	if !containsString(group.GroupMembers, username) {
		ErrorResponse := ErrorResponse{
			Error: "Group exists, but you do not have permission to view it",
		}
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse)
	}

	token, err := addConnectionRequest(username, body.GroupName)
	if err != nil {
		ErrorResponse := ErrorResponse{
			Error: "Failed to create connect token",
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse)
	}

	loginResponse := LoginResponse{
		ConnectToken: token,
	}
	return c.Status(fiber.StatusOK).JSON(loginResponse)
}
