package main

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var database *mongo.Database
var mongoContext = context.TODO()

func initMongo(config Config) {
	clientOptions := options.Client().ApplyURI(config.MongoDbConnectionString)
	client, err := mongo.Connect(mongoContext, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(mongoContext, nil)
	if err != nil {
		log.Fatal(err)
	}

	database = client.Database("sebschat")
	fmt.Println("Connected to MongoDB")
}

func getUsernameByToken(authToken string) (string, error) {
	if authToken == "" {
		return "", fmt.Errorf("auth token is required")
	}

	usersCollection := database.Collection("users")
	var user struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}
	err := usersCollection.FindOne(mongoContext, map[string]interface{}{
		"token": authToken,
	}).Decode(&user)

	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	return user.Username, nil
}
