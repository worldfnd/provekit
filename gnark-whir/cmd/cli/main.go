package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/urfave/cli/v2"

	"reilabs/whir-verifier-circuit/app/circuit"

	gnark_nimue "github.com/reilabs/gnark-nimue"
	go_ark_serialize "github.com/reilabs/go-ark-serialize"
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

			io := gnark_nimue.IOPattern{}
			err = io.Parse([]byte(config.IOPattern))
			if err != nil {
				return fmt.Errorf("failed to parse IO pattern: %w", err)
			}

			var pointer uint64
			var truncated []byte

			var merklePaths []circuit.MultiPath[circuit.KeccakDigest]
			var stirAnswers [][][]circuit.Fp256
			var deferred []circuit.Fp256
			var claimedEvaluations []circuit.Fp256

			for _, op := range io.Ops {
				switch op.Kind {
				case gnark_nimue.Hint:
					if pointer+4 > uint64(len(config.Transcript)) {
						return fmt.Errorf("insufficient bytes for hint length")
					}
					hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
					start := pointer + 4
					end := start + uint64(hintLen)

					if end > uint64(len(config.Transcript)) {
						return fmt.Errorf("insufficient bytes for merkle proof")
					}

					switch string(op.Label) {
					case "merkle_proof":
						var path circuit.MultiPath[circuit.KeccakDigest]
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&path,
							false, false,
						)
						merklePaths = append(merklePaths, path)
					case "stir_answers":
						var stirAnswersTemporary [][]circuit.Fp256
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&stirAnswersTemporary,
							false, false,
						)
						stirAnswers = append(stirAnswers, stirAnswersTemporary)
					case "deferred_weight_evaluations":
						var deferredTemporary []circuit.Fp256
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&deferredTemporary,
							false, false,
						)
						if err != nil {
							return fmt.Errorf("failed to deserialize deferred hint: %w", err)
						}
						deferred = append(deferred, deferredTemporary...)
					case "claimed_evaluations":
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&claimedEvaluations,
							false, false,
						)
						if err != nil {
							return fmt.Errorf("failed to deserialize claimed_evaluations: %w", err)
						}
					}

					if err != nil {
						return fmt.Errorf("failed to deserialize merkle proof: %w", err)
					}

					pointer = end

				case gnark_nimue.Absorb:
					start := pointer
					if string(op.Label) == "pow-nonce" {
						pointer += op.Size
					} else {
						pointer += op.Size * 32
					}

					if pointer > uint64(len(config.Transcript)) {
						return fmt.Errorf("absorb exceeds transcript length")
					}

					truncated = append(truncated, config.Transcript[start:pointer]...)
				}
			}

			config.Transcript = truncated

			r1csFile, r1csErr := os.ReadFile(r1csFilePath)
			if r1csErr != nil {
				return fmt.Errorf("failed to read r1cs file: %w", r1csErr)
			}

			var r1cs circuit.R1CS
			if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
				return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
			}

			internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
			if err != nil {
				return fmt.Errorf("failed to decode interner values: %w", err)
			}

			var interner circuit.Interner
			_, err = go_ark_serialize.CanonicalDeserializeWithMode(
				bytes.NewReader(internerBytes), &interner, false, false,
			)
			if err != nil {
				return fmt.Errorf("failed to deserialize interner: %w", err)
			}

			var pk *groth16.ProvingKey
			var vk *groth16.VerifyingKey
			if pkPath != "" && vkPath != "" {
				log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
				restoredPk, restoredVk, err := circuit.KeysFromFiles(pkPath, vkPath)
				if err != nil {
					return err
				}
				pk = &restoredPk
				vk = &restoredVk
				log.Printf("Successfully loaded PK/VK")
			}

			spartanEnd := config.WHIRConfigCol.NRounds + 1

			hints := circuit.Hints{
				ColHints: circuit.Hint{
					MerklePaths: merklePaths[:spartanEnd],
					StirAnswers: stirAnswers[:spartanEnd],
				},
			}

			err = circuit.VerifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, r1cs, interner)
			if err != nil {
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
