package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/urfave/cli/v2"

	"reilabs/whir-verifier-circuit/app/circuit"
)

func main() {
	app := &cli.App{
		Name:  "Verifier",
		Usage: "Verifies proof with given parameters",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Usage:    "Path to the config file",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "ccs",
				Usage:    "Optional path to store the constraint system object",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "r1cs",
				Usage:    "Path to the r1cs json file",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "r1cs_url",
				Usage:    "Optional publicly downloadable URL to the r1cs file",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "pk_url",
				Usage:    "Optional publicly downloadable URL to the proving key",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "vk_url",
				Usage:    "Optional publicly downloadable URL to the verifying key",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name: "pk",
				Usage: "Optional path to load Proving Key from (if not provided, " +
					"PK and VK will be generated unsafely)",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name: "vk",
				Usage: "Optional path to load Verifying Key from (if not provided, " +
					"PK and VK will be generated unsafely)",
				Required: false,
				Value:    "",
			},
		},
		Action: func(c *cli.Context) error {
			configFilePath := c.String("config")
			r1csFilePath := c.String("r1cs")
			outputCcsPath := c.String("ccs")
			pkPath := c.String("pk")
			vkPath := c.String("vk")
			pkUrl := c.String("pk_url")
			vkUrl := c.String("vk_url")
			r1csUrl := c.String("r1cs_url")

			configFile, err := os.ReadFile(configFilePath)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}

			var config circuit.Config
			if err := json.Unmarshal(configFile, &config); err != nil {
				return fmt.Errorf("failed to unmarshal config JSON: %w", err)
			}

			var r1csFile []byte
			if r1csFilePath != "" {
				r1csFile, err = os.ReadFile(r1csFilePath)
				if err != nil {
					return fmt.Errorf("failed to read r1cs file: %w", err)
				}
			} else {
				r1csFile, err = circuit.GetR1csFromUrl(r1csUrl)
				if err != nil {
					return fmt.Errorf("failed to get R1CS from URL: %w", err)
				}
			}

			var r1cs circuit.R1CS
			if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
				return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
			}

			var pk *groth16.ProvingKey
			var vk *groth16.VerifyingKey

			if pkUrl != "" && vkUrl != "" {
				pk, vk, err = circuit.GetPkAndVkFromUrl(pkUrl, vkUrl)
				if err != nil {
					return fmt.Errorf("failed to get PK/VK: %w", err)
				}
			} else if pkPath != "" && vkPath != "" {
				pk, vk, err = circuit.GetPkAndVkFromPath(pkPath, vkPath)
				if err != nil {
					return fmt.Errorf("failed to get PK/VK: %w", err)
				}
			} else {
				log.Printf("No valid PK/VK url or file combo provided, generating new keys unsafely")
			}

			if err = circuit.PrepareAndVerifyCircuit(config, r1cs, pk, vk, outputCcsPath); err != nil {
				return fmt.Errorf("failed to prepare and verify circuit: %w", err)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
