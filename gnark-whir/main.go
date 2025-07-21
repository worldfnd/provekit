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
	StatementValuesAtRandomPoint []Fp256 `json:"statement_values_at_random_point"`
}

type Config struct {
	LogNumConstraints            int      `json:"log_num_constraints"`
	NRounds                      int      `json:"n_rounds"`
	NVars                        int      `json:"n_vars"`
	FoldingFactor                []int    `json:"folding_factor"`
	OODSamples                   []int    `json:"ood_samples"`
	NumQueries                   []int    `json:"num_queries"`
	PowBits                      []int    `json:"pow_bits"`
	FinalQueries                 int      `json:"final_queries"`
	FinalPowBits                 int      `json:"final_pow_bits"`
	FinalFoldingPowBits          int      `json:"final_folding_pow_bits"`
	DomainGenerator              string   `json:"domain_generator"`
	Rate                         int      `json:"rate"`
	IOPattern                    string   `json:"io_pattern"`
	Transcript                   []byte   `json:"transcript"`
	TranscriptLen                int      `json:"transcript_len"`
	WitnessStatementEvaluations  []string `json:"witness_statement_evaluations"`
	BlindingStatementEvaluations []string `json:"blinding_statement_evaluations"`
}

type SparseMatrix struct {
	Rows       uint64   `json:"num_rows"`
	Cols       uint64   `json:"num_cols"`
	RowIndices []uint64 `json:"new_row_indices"`
	ColIndices []uint64 `json:"col_indices"`
	Values     []uint64 `json:"values"`
}

type Interner struct {
	Values []Fp256 `json:"values"`
}

type InternerAsString struct {
	Values string `json:"values"`
}

type R1CS struct {
	PublicInputs uint64           `json:"public_inputs"`
	Witnesses    uint64           `json:"witnesses"`
	Constraints  uint64           `json:"constraints"`
	Interner     InternerAsString `json:"interner"`
	A            SparseMatrix     `json:"a"`
	B            SparseMatrix     `json:"b"`
	C            SparseMatrix     `json:"c"`
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
				Name:     "r1cs",
				Usage:    "Path to the r1cs json file",
				Required: false,
				Value:    "../noir-examples/poseidon-rounds/r1cs.json",
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
			r1csFilePath := c.String("r1cs")
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
			fmt.Printf("io: %s\n", io.PPrint())

			var pointer uint64
			var truncated []byte

			var first_round_merkle_paths []ProofElement
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

					case "first_round_merkle_proof":
						var path []ProofElement
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&path,
							false, false,
						)
						first_round_merkle_paths = path
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
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&deferred,
							false, false,
						)
						if err != nil {
							return fmt.Errorf("failed to deserialize deferred hint: %w", err)
						}
						fmt.Print(deferred)
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

			var r1cs R1CS
			if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
				return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
			}

			internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
			if err != nil {
				return fmt.Errorf("failed to decode interner values: %w", err)
			}

			var interner Interner
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
				restoredPk, restoredVk, err := keys_from_files(pkPath, vkPath)
				if err != nil {
					return err
				}
				pk = &restoredPk
				vk = &restoredVk
			}

			verify_circuit(deferred, config, r1cs, interner, first_round_merkle_paths, merkle_paths, stir_answers, pk, vk, outputCcsPath)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
