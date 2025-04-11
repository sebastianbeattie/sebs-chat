package main

import (
	"log"
	"os"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

func main() {
	var config Config = Config{
		MongoDbConnectionString: os.Getenv("MONGODB_CONNECTION_STRING"),
		ServerPort:              os.Getenv("SERVER_PORT"),
	}

	initMongo(config)

	app := fiber.New()

	// Test endpoint
	app.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// WebSocket endpoint
	app.Get("/ws", websocket.New(websocketHandler))

	// User endpoints
	app.Post("/user/register", register)
	app.Post("/user/memberships", getUserMemberships)
	app.Post("/user/login", login)

	// Group endpoints
	app.Post("/group/create", createGroup)
	app.Post("/group/:name", getGroup)

	log.Fatal(app.Listen(":" + config.ServerPort))
}
