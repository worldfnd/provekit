package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/urfave/cli/v2"

	gnark_nimue "github.com/reilabs/gnark-nimue"
	go_ark_serialize "github.com/reilabs/go-ark-serialize"
)

type KeccakDigest struct {
	KeccakDigest [32]uint8
}

type Fp256 struct {
	Limbs [4]uint64
}

type MultiPath[Digest any] struct {
	LeafSiblingHashes      []Digest
	AuthPathsPrefixLengths []uint64
	AuthPathsSuffixes      [][]Digest
	LeafIndexes            []uint64
}

type ProofElement struct {
	A MultiPath[KeccakDigest]
	B [][]Fp256
}

type ProofObject struct {
	StatementValuesAtRandomPoint []Fp256
}

type Config struct {
	WHIRConfigCol        WHIRConfig `json:"whir_config_col"`
	WHIRConfigA          WHIRConfig `json:"whir_config_a_num_terms"`
	LogNumConstraints    int        `json:"log_num_constraints"`
	IOPattern            string     `json:"io_pattern"`
	Transcript           []byte     `json:"transcript"`
	TranscriptLen        int        `json:"transcript_len"`
	StatementEvaluations []string   `json:"statement_evaluations"`
}

type WHIRConfig struct {
	NRounds             int    `json:"n_rounds"`
	Rate                int    `json:"rate"`
	NVars               int    `json:"n_vars"`
	FoldingFactor       []int  `json:"folding_factor"`
	OODSamples          []int  `json:"ood_samples"`
	NumQueries          []int  `json:"num_queries"`
	PowBits             []int  `json:"pow_bits"`
	FinalQueries        int    `json:"final_queries"`
	FinalPowBits        int    `json:"final_pow_bits"`
	FinalFoldingPowBits int    `json:"final_folding_pow_bits"`
	DomainGenerator     string `json:"domain_generator"`
}

type Hints struct {
	col_hints Hint
	a_hints   Hint
}

type Hint struct {
	merkle_paths []MultiPath[KeccakDigest]
	stir_answers [][][]Fp256
}

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
			outputCcsPath := c.String("ccs")
			pkPath := c.String("pk")
			vkPath := c.String("vk")

			configFile, err := os.ReadFile(configFilePath)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}

			var config Config
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

			var merkle_paths []MultiPath[KeccakDigest]
			var stir_answers [][][]Fp256
			var deferred []Fp256

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
						var path MultiPath[KeccakDigest]
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&path,
							false, false,
						)
						merkle_paths = append(merkle_paths, path)
					case "stir_answers":
						var stirAnswers [][]Fp256
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&stirAnswers,
							false, false,
						)
						stir_answers = append(stir_answers, stirAnswers)
					case "deferred_weight_evaluations":
						var deferred_temp []Fp256
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&deferred_temp,
							false, false,
						)
						if err != nil {
							return fmt.Errorf("failed to deserialize deferred hint: %w", err)
						}
						deferred = append(deferred, deferred_temp...)
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

			var pk *groth16.ProvingKey
			var vk *groth16.VerifyingKey
			if pkPath != "" && vkPath != "" {
				log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
				restoredPk, restoredVk, err := keys_from_files(pkPath, vkPath)
				if err != nil {
					return err
				}
				pk = &restoredPk
				vk = &restoredVk
			}

			spartan_end := config.WHIRConfigCol.NRounds + 1
			spark_val_end := spartan_end + (config.WHIRConfigA.NRounds + 1)

			hints := Hints{
				col_hints: Hint{
					merkle_paths: merkle_paths[:spartan_end],
					stir_answers: stir_answers[:spartan_end],
				},
				a_hints: Hint{
					merkle_paths: merkle_paths[spartan_end:spark_val_end],
					stir_answers: stir_answers[spartan_end:spark_val_end],
				},
			}
			fmt.Print(config.StatementEvaluations)
			verify_circuit(deferred, config, hints, pk, vk, outputCcsPath)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
