package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

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
				Value:    "../noir-examples/poseidon-rounds/params_for_recursive_verifier",
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
				Value:    "../noir-examples/poseidon-rounds/r1cs.json",
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

			configFile, err := os.ReadFile(configFilePath)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}

			var config circuit.Config
			if err := json.Unmarshal(configFile, &config); err != nil {
				return fmt.Errorf("failed to unmarshal config JSON: %w", err)
			}

			r1csFile, r1csErr := os.ReadFile(r1csFilePath)
			if r1csErr != nil {
				return fmt.Errorf("failed to read r1cs file: %w", r1csErr)
			}

			var r1cs circuit.R1CS
			if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
				return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
			}

			if err := circuit.PrepareAndVerifyCircuit(config, r1cs, vkPath, pkPath, outputCcsPath); err != nil {
				return fmt.Errorf("failed to verify circuit: %w", err)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
