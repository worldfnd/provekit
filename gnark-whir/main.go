package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"log"
	"os"

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
	FirstRoundPaths              []ProofElement `json:"round0_merkle_paths"`
	MerklePaths                  []ProofElement `json:"merkle_paths"`
	StatementValuesAtRandomPoint []Fp256        `json:"statement_values_at_random_point"`
}

type Config struct {
	LogNumConstraints    int      `json:"log_num_constraints"`
	NRounds              int      `json:"n_rounds"`
	NVars                int      `json:"n_vars"`
	FoldingFactor        []int    `json:"folding_factor"`
	OODSamples           []int    `json:"ood_samples"`
	NumQueries           []int    `json:"num_queries"`
	PowBits              []int    `json:"pow_bits"`
	FinalQueries         int      `json:"final_queries"`
	FinalPowBits         int      `json:"final_pow_bits"`
	FinalFoldingPowBits  int      `json:"final_folding_pow_bits"`
	DomainGenerator      string   `json:"domain_generator"`
	Rate                 int      `json:"rate"`
	IOPattern            string   `json:"io_pattern"`
	Transcript           []byte   `json:"transcript"`
	TranscriptLen        int      `json:"transcript_len"`
	StatementEvaluations []string `json:"statement_evaluations"`
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
				Name:     "proof",
				Usage:    "Path to the proof file",
				Required: false,
				Value:    "../noir-examples/poseidon-rounds/proof_for_recursive_verifier",
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
			proofFilePath := c.String("proof")
			configFilePath := c.String("config")
			r1csFilePath := c.String("r1cs")
			outputCcsPath := c.String("ccs")
			pkPath := c.String("pk")
			vkPath := c.String("vk")

			proofFile, err := os.Open(proofFilePath)
			if err != nil {
				return fmt.Errorf("failed to open proof file to read: %w", err)
			}

			var proof ProofObject
			_, err = go_ark_serialize.CanonicalDeserializeWithMode(proofFile, &proof, false, false)
			if err != nil {
				return fmt.Errorf("failed to deserialize proof file: %w", err)
			}

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

			verify_circuit(proof, config, r1cs, interner, pk, vk, outputCcsPath)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
