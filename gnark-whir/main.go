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
	WHIRConfigRow     WHIRConfig `json:"whir_config_row"`
	WHIRConfigCol     WHIRConfig `json:"whir_config_col"`
	WHIRConfigA       WHIRConfig `json:"whir_config_a_num_terms"`
	WHIRConfigB       WHIRConfig `json:"whir_config_b_num_terms"`
	WHIRConfigC       WHIRConfig `json:"whir_config_c_num_terms"`
	LogNumConstraints int        `json:"log_num_constraints"`
	LogNumVariables   int        `json:"log_num_variables"`
	LogANumTerms      int        `json:"log_a_num_terms"`
	LogBNumTerms      int        `json:"log_b_num_terms"`
	LogCNumTerms      int        `json:"log_c_num_terms"`
	IOPattern         string     `json:"io_pattern"`
	Transcript        []byte     `json:"transcript"`
	TranscriptLen     int        `json:"transcript_len"`
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
	spartanHints Hint
	matrixA      SparkHints
}

type SparkHints struct {
	SumcheckValHints Hint
	SumcheckERXHints Hint
	SumcheckERYHints Hint
	rowwise          MemoryCheckHints
	colwise          MemoryCheckHints
}

type Hint struct {
	merklePaths []MultiPath[KeccakDigest]
	stirAnswers [][][]Fp256
}

type MemoryCheckHints struct {
	FinalGPAFinalCTRHints Hint
	RSGPAAddrHints        Hint
	RSGPAValueHints       Hint
	RSGPATimeStampHints   Hint
	WSGPAAddrHints        Hint
	WSGPAValueHints       Hint
	WSGPATimeStampHints   Hint
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

			var combinedWHIRHints Hint
			var deferred []Fp256
			var claimedEvaluations []Fp256
			var sumcheck_last_folds []Fp256

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
						combinedWHIRHints.merklePaths = append(combinedWHIRHints.merklePaths, path)
					case "stir_answers":
						var stirAnswersTemporary [][]Fp256
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&stirAnswersTemporary,
							false, false,
						)
						combinedWHIRHints.stirAnswers = append(combinedWHIRHints.stirAnswers, stirAnswersTemporary)
					case "deferred_weight_evaluations":
						var deferredTemporary []Fp256
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
					case "sumcheck_last_folds":
						_, err = go_ark_serialize.CanonicalDeserializeWithMode(
							bytes.NewReader(config.Transcript[start:end]),
							&sumcheck_last_folds,
							false, false,
						)
						if err != nil {
							return fmt.Errorf("failed to deserialize sumcheck_last_folds: %w", err)
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

			var pk *groth16.ProvingKey
			var vk *groth16.VerifyingKey
			if pkPath != "" && vkPath != "" {
				log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
				restoredPk, restoredVk, err := keysFromFiles(pkPath, vkPath)
				if err != nil {
					return err
				}
				pk = &restoredPk
				vk = &restoredVk
			}

			hints := Hints{}
			hints.spartanHints, combinedWHIRHints = parseHint(combinedWHIRHints, config.WHIRConfigCol.NRounds+1)
			hints.matrixA.SumcheckValHints, combinedWHIRHints = parseHint(combinedWHIRHints, config.WHIRConfigA.NRounds+1)
			hints.matrixA.SumcheckERXHints, combinedWHIRHints = parseHint(combinedWHIRHints, config.WHIRConfigA.NRounds+1)
			hints.matrixA.SumcheckERYHints, combinedWHIRHints = parseHint(combinedWHIRHints, config.WHIRConfigA.NRounds+1)
			hints.matrixA.rowwise, combinedWHIRHints = parseMemoryCheckHints(combinedWHIRHints, config.WHIRConfigRow.NRounds, config.WHIRConfigA.NRounds)
			hints.matrixA.colwise, combinedWHIRHints = parseMemoryCheckHints(combinedWHIRHints, config.WHIRConfigRow.NRounds, config.WHIRConfigA.NRounds)

			verifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, sumcheck_last_folds)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func parseHint(combined Hint, n int) (parsed, remaining Hint) {
	parsed = Hint{
		merklePaths: combined.merklePaths[:n],
		stirAnswers: combined.stirAnswers[:n],
	}

	remaining = Hint{
		merklePaths: combined.merklePaths[n:],
		stirAnswers: combined.stirAnswers[n:],
	}

	return
}

func parseMemoryCheckHints(combined Hint, memoryRounds int, numTermsRounds int) (parsed MemoryCheckHints, remaining Hint) {
	parsed.FinalGPAFinalCTRHints, combined = parseHint(combined, (memoryRounds + 1))
	parsed.RSGPAAddrHints, combined = parseHint(combined, (numTermsRounds + 1))
	parsed.RSGPAValueHints, combined = parseHint(combined, (numTermsRounds + 1))
	parsed.RSGPATimeStampHints, combined = parseHint(combined, (numTermsRounds + 1))
	parsed.WSGPAAddrHints, combined = parseHint(combined, (numTermsRounds + 1))
	parsed.WSGPAValueHints, combined = parseHint(combined, (numTermsRounds + 1))
	parsed.WSGPATimeStampHints, combined = parseHint(combined, (numTermsRounds + 1))

	remaining = combined
	return
}
