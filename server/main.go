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
	app.Use("/ws", func(c *fiber.Ctx) error {
		token := c.Query("token")
		if token == "" {
			return c.Status(401).SendString("Missing connection token")
		}

		valid := validateConnectionToken(token)
		if !valid {
			return c.Status(401).SendString("Invalid connection token")
		}

		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
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
