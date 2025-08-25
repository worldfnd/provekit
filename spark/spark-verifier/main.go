package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	spark_proof_file, err := os.ReadFile("../spark-prover/spark_proof")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read config file: %v\n", err)
		os.Exit(1)
	}

	var spark_proof SPARKProof
	if err := json.Unmarshal(spark_proof_file, &spark_proof); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unmarshal config JSON: %v\n", err)
		os.Exit(1)
	}
}

type SPARKProof struct {
	Transcript []byte `json:"transcript"`
}
