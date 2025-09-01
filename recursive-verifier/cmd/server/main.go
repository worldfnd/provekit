package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"reilabs/whir-verifier-circuit/app/circuit"
)

// main initializes and starts the WHIR verifier HTTP server.
// The server provides endpoints for proof verification with configurable timeouts and CORS settings.
func main() {
	fiberConfig := fiber.Config{
		ReadTimeout:  10 * time.Minute,       // 10 min for file upload (params and r1cs.json)
		WriteTimeout: 5 * time.Minute,        // since response is just success/failure
		IdleTimeout:  90 * time.Minute,       // 90 min total connection time (for processing)
		BodyLimit:    2 * 1024 * 1024 * 1024, // 2GB limit (total size params and r1cs.json)
		Prefork:      false,
		// CaseSensitive: true,
		// StrictRouting: true,
		ServerHeader: "Recursive-Verifier",
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
		return verify(c)
	})

	log.Fatal(app.Listen(":3000"))
}

func ping(c *fiber.Ctx) error {
	return c.SendString("pong")
}

// verify handles POST requests to verify WHIR proofs.
// It accepts R1CS data, configuration, and proving/verifying keys via form data or URLs.
func verify(c *fiber.Ctx) error {
	outputCcsPath := c.FormValue("output_ccs_path") // Optional path for CCS output
	pkUrl := c.FormValue("pk_url")
	vkUrl := c.FormValue("vk_url")
	r1csUrl := c.FormValue("r1cs_url")

	var r1csFile []byte
	var err error

	if r1csUrl != "" {
		r1csFile, err = circuit.GetR1csFromUrl(r1csUrl)
		if err != nil {
			return fmt.Errorf("failed to get R1CS from URL: %w", err)
		}
	} else {
		r1csFile, err = getFile(c, "r1cs")
		if err != nil {
			return fmt.Errorf("failed to get R1CS file: %w", err)
		}
	}

	var r1cs circuit.R1CS
	if err := json.Unmarshal(r1csFile, &r1cs); err != nil {
		return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
	}

	configFile, err := getFile(c, "config")
	if err != nil {
		log.Printf("Failed to get config file: %v", err)
		return c.Status(400).SendString("Failed to get config file")
	}

	var config circuit.Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config JSON: %w", err)
	}

	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey

	if vkUrl != "" && pkUrl != "" {
		pk, vk, err = circuit.GetPkAndVkFromUrl(pkUrl, vkUrl)
		if err != nil {
			log.Printf("Failed to get PK/VK from URL: %v", err)
			return c.Status(400).JSON(fiber.Map{
				"error":   "Failed to fetch keys",
				"details": err.Error(),
			})
		}
	} else {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Missing required parameters",
			"details": "Both pk_url and vk_url must be provided",
		})
	}

	if err := circuit.PrepareAndVerifyCircuit(config, r1cs, pk, vk, outputCcsPath); err != nil {
		log.Printf("Verification failed: %v", err)
		return c.Status(400).JSON(fiber.Map{
			"error":   "Verification failed",
			"details": err.Error(),
		})
	}

	log.Printf("Verification successful")
	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Verification completed successfully",
	})
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
