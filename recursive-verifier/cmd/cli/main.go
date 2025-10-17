package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/urfave/cli/v2"

	"reilabs/whir-verifier-circuit/pkg/verifier/circuit"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
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
			&cli.StringFlag{
				Name:     "saveKeys",
				Usage:    "Optional path to save keys to files",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "spark_config",
				Usage:    "Path to the spark SPARK proof file",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "evaluation",
				Usage:    "Option to directly evaluate the matrix extension or use SPARK",
				Required: true,
				Action: func(c *cli.Context, v string) error {
					if v != "direct" && v != "spark" {
						return fmt.Errorf("invalid value for --evaluation: %s (expected 'direct' or 'spark')", v)
					}
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			ctx := context.Background()
			buildOps := circuit.BuildOptions{
				ConfigFilePath:      c.String("config"),
				SparkConfigFilePath: c.String("spark_config"),
				Evaluation:          c.String("evaluation"),
				R1CSFilePath:        c.String("r1cs"),
				R1CSURL:             c.String("r1cs_url"),
				PkPath:              c.String("pk"),
				VkPath:              c.String("vk"),
				PkURL:               c.String("pk_url"),
				VkURL:               c.String("vk_url"),
				OutputCcsPath:       c.String("ccs"),
				SaveKeys:            c.String("saveKeys"),
			}

			// Read config file
			configFile, err := os.ReadFile(buildOps.ConfigFilePath)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}

			var config types.Config
			if err := json.Unmarshal(configFile, &config); err != nil {
				return fmt.Errorf("failed to unmarshal config JSON: %w", err)
			}

			// TODO: Only parse SPARK file if evaluation flag is set to spark
			sparkConfigFile, err := os.ReadFile(buildOps.SparkConfigFilePath)
			if err != nil {
				return fmt.Errorf("failed to read spark config file: %w", err)
			}

			var sparkConfig types.SparkConfig
			if err := json.Unmarshal(sparkConfigFile, &sparkConfig); err != nil {
				return fmt.Errorf("failed to unmarshal spark config JSON: %w", err)
			}

			var r1csFile []byte
			if buildOps.HasR1CSFile() {
				r1csFile, err = os.ReadFile(buildOps.R1CSFilePath)
				if err != nil {
					return fmt.Errorf("failed to read r1cs file: %w", err)
				}
			} else if buildOps.HasR1CSURL() {
				r1csFile, err = circuit.LoadR1CSFromURL(ctx, buildOps.R1CSURL)
				if err != nil {
					return fmt.Errorf("failed to get R1CS from URL: %w", err)
				}
			} else {
				return fmt.Errorf("either r1cs file path or r1cs_url must be provided")
			}

			// Parse only if we use direct evaluation
			var r1cs types.R1CS
			if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
				return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
			}

			var pk *groth16.ProvingKey
			var vk *groth16.VerifyingKey

			switch {
			case buildOps.HasPkAndVkFromURL():
				pk, vk, err = circuit.LoadKeys(ctx, buildOps.PkURL, buildOps.VkURL)
				if err != nil {
					return fmt.Errorf("failed to load PK/VK: %w", err)
				}
			case buildOps.HasPkAndVkFromPath():
				pk, vk, err = circuit.LoadKeys(ctx, buildOps.PkPath, buildOps.VkPath)
				if err != nil {
					return fmt.Errorf("failed to load PK/VK: %w", err)
				}
			default:
				log.Printf("No valid PK/VK url or file combo provided, generating new keys unsafely")
			}

			if err = circuit.PrepareAndVerifyCircuit(config, sparkConfig, r1cs, pk, vk, buildOps); err != nil {
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
