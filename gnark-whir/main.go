package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

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
	configFile, err := os.ReadFile("../noir-examples/poseidon-rounds/params_for_recursive_verifier")
	if err != nil {
		fmt.Println(err)
		return
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v\n", err)
	}

	io := gnark_nimue.IOPattern{}
	err = io.Parse([]byte(config.IOPattern))
	if err != nil {
		fmt.Println(err)
		return
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
				fmt.Println("insufficient bytes for hint length")
				return
			}
			hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(config.Transcript)) {
				fmt.Println("insufficient bytes for merkle proof")
				return
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
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferred,
					false, false,
				)
				if err != nil {
					fmt.Println("failed to deserialize deferred hint:", err)
					return
				}
				fmt.Print(deferred)
			}

			if err != nil {
				fmt.Println("failed to deserialize merkle proof:", err)
				return
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
				fmt.Println("absorb exceeds transcript length")
				return
			}

			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

	r1csFile, r1csErr := os.ReadFile("../noir-examples/poseidon-rounds/r1cs.json")
	if r1csErr != nil {
		fmt.Println(err)
		return
	}

	var r1cs R1CS
	if err := json.Unmarshal(r1csFile, &r1cs); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v\n", err)
	}

	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		fmt.Println(err)
		return
	}

	var interner Interner
	_, err = go_ark_serialize.CanonicalDeserializeWithMode(bytes.NewReader(internerBytes), &interner, false, false)
	if err != nil {
		fmt.Println(err)
		return
	}

	verify_circuit(deferred, config, r1cs, interner, merkle_paths, stir_answers)
}
