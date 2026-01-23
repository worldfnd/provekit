package circuit

import (
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Common types
type KeccakDigest struct {
	KeccakDigest [32]uint8
}

type Fp256 struct {
	Limbs [4]uint64
}

type Path[Digest any] struct {
	LeafSiblingHash Digest
	AuthPath        []Digest
	LeafIndex       uint64
}

type FullMultiPath[Digest any] struct {
	Proofs []Path[Digest]
}

// WHIR specific types
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
	BatchSize           int    `json:"batch_size"`
}

type WHIRParams struct {
	ParamNRounds                         int
	FoldingFactorArray                   []int
	RoundParametersOODSamples            []int
	RoundParametersNumOfQueries          []int
	PowBits                              []int
	FinalQueries                         int
	FinalPowBits                         int
	FinalFoldingPowBits                  int
	StartingDomainBackingDomainGenerator frontend.Variable
	DomainSize                           int
	CommittmentOODSamples                int
	FinalSumcheckRounds                  int
	MVParamsNumberOfVariables            int
	BatchSize                            int
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

// Merkle specific types
type MerklePaths struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][][]uints.U8
	AuthPaths         [][][][]uints.U8
}

type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][]frontend.Variable
	AuthPaths         [][][]frontend.Variable
}

// Other types
type ProofObject struct {
	StatementValuesAtRandomPoint []Fp256 `json:"statement_values_at_random_point"`
}

type Config struct {
	WHIRConfigWitness            WHIRConfig   `json:"whir_config_witness"`
	WHIRConfigHidingSpartan      WHIRConfig   `json:"whir_config_hiding_spartan"`
	LogNumConstraints            int          `json:"log_num_constraints"`
	LogNumVariables              int          `json:"log_num_variables"`
	LogANumTerms                 int          `json:"log_a_num_terms"`
	IOPattern                    string       `json:"io_pattern"`
	Transcript                   []byte       `json:"transcript"`
	TranscriptLen                int          `json:"transcript_len"`
	WitnessStatementEvaluations  []string     `json:"witness_statement_evaluations"`
	BlindingStatementEvaluations []string     `json:"blinding_statement_evaluations"`
	NumChallenges                int          `json:"num_challenges"`
	W1Size                       int          `json:"w1_size"`
	PublicInputs                 PublicInputs `json:"public_inputs"`
}

// Update Hints to support batch mode
type Hints struct {
	spartanHidingHint ZKHint

	// Witness hints (length 1 for single mode, N for batch mode)
	WitnessFirstRoundHints []FirstRoundHint

	// Single mode: rounds 1+ for the one commitment
	// Batch mode: rounds 1+ for batched polynomial
	WitnessRoundHints ZKHint
}

type Hint struct {
	merklePaths []FullMultiPath[KeccakDigest]
	stirAnswers [][][]Fp256
}

type FirstRoundHint struct {
	path                Hint
	expectedStirAnswers [][]Fp256
}

type ZKHint struct {
	firstRoundMerklePaths FirstRoundHint
	roundHints            Hint
}

type ClaimedEvaluations struct {
	FSums []Fp256
	GSums []Fp256
}

type DualClaimedEvaluations struct {
	First  ClaimedEvaluations
	Second ClaimedEvaluations
}

type PublicInputs struct {
	Values []frontend.Variable
}

func (p *PublicInputs) UnmarshalJSON(data []byte) error {
	values, err := utilities.UnmarshalPublicInputs(data)
	if err != nil {
		return err
	}
	p.Values = values
	return nil
}

func (p *PublicInputs) IsEmpty() bool {
	return len(p.Values) == 0
}
