package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"reilabs/whir-verifier-circuit/app/circuit"
)

func main() {
	fiberConfig := fiber.Config{
		ReadTimeout:  10 * time.Minute,       // 10 min for file upload (params and r1cs.json)
		WriteTimeout: 5 * time.Minute,        // since response is just success/failure
		IdleTimeout:  90 * time.Minute,       // 90 min total connection time (for processing)
		BodyLimit:    2 * 1024 * 1024 * 1024, // 2GB limit (total size params and r1cs.json)
		Prefork:      false,
		// CaseSensitive: true,
		// StrictRouting: true,
		ServerHeader: "Gnark-Whir",
		AppName:      "Verifier Server",
	}

	app := fiber.New(fiberConfig)

	corsConfig := cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Content-Length, Authorization, Cookie",
		AllowMethods: "GET, POST, PUT, DELETE, PATCH",
		MaxAge:       12 * 3600,
	}
	app.Use(cors.New(corsConfig))

	api := app.Group("/api")
	v1 := api.Group("/v1")

	v1.Get("/ping", ping)

	v1.Post("/verify", func(c *fiber.Ctx) error {
		return getFileAndVerify(c, "", "")
	})

	v1.Post("/verifybasic2", func(c *fiber.Ctx) error {
		return getFileAndVerify(c, "keys/basic2_vk.bin", "keys/basic2_pk.bin")
	})
	v1.Post("/verifyagecheck", func(c *fiber.Ctx) error {
		return getFileAndVerify(c, "keys/age_check_vk.bin", "keys/age_check_pk.bin")
	})

	log.Fatal(app.Listen(":3000"))
}

func ping(c *fiber.Ctx) error {
	return c.SendString("pong")
}

func getFileAndVerify(c *fiber.Ctx, vkPath string, pkPath string) error {
	outputCcsPath := "" // TODO

	r1csFile, err := getFile(c, "r1cs")
	if err != nil {
		log.Printf("Failed to get R1CS file: %v", err)
		return c.Status(400).SendString("Failed to get R1CS file")
	}

	configFile, err := getFile(c, "config")
	if err != nil {
		log.Printf("Failed to get config file: %v", err)
		return c.Status(400).SendString("Failed to get config file")
	}

	if vkPath != "" && pkPath != "" {
		err = verify(configFile, r1csFile, vkPath, pkPath, outputCcsPath)
	} else {
		err = verify(configFile, r1csFile, "", "", outputCcsPath)
	}

	if err != nil {
		log.Printf("Verification failed: %v", err)
		return c.Status(400).SendString("Verification failed")
	}

	log.Printf("Verification successful")
	return c.SendString("Verification successful")
}

func verify(configFile []byte, r1csFile []byte, vkPath string, pkPath string, outputCcsPath string) error {
	// outputCcsPath := "" // TODO : Handle returning/saving, what to do with Ccs File

	var config circuit.Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config JSON: %w", err)
	}

	var r1cs circuit.R1CS
	if err := json.Unmarshal(r1csFile, &r1cs); err != nil {
		return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
	}

	pk, vk, err := circuit.GetPkAndVkFromPath(pkPath, vkPath)
	if err != nil {
		return fmt.Errorf("failed to get PK/VK: %w", err)
	}

	if err := circuit.PrepareAndVerifyCircuit(config, r1cs, pk, vk, outputCcsPath); err != nil {
		return fmt.Errorf("failed to verify circuit: %w", err)
	}

	return nil
}

func getFile(c *fiber.Ctx, name string) ([]byte, error) {

	fileHeader, err := c.FormFile(name)
	if err != nil {
		return nil, fmt.Errorf("no %s file provided: %w", name, err)
	}

	f, err := fileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file: %w", name, err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Printf("failed to close %s file: %v", name, err)
		}
	}()

	file, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file: %w", name, err)
	}

	return file, nil
}
