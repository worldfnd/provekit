package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Common types
type Digest struct {
	Digest [32]uint8
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

type FullMultiPathWithCapping[Digest any] struct {
	Proofs       []Path[Digest]
	CapContainer []Digest
}

type MultiIndexMerkleTreeProof[Digest any] struct {
	Depth   uint64
	Indices []uint64
	Proof   []Digest
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

type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][]frontend.Variable
	AuthPaths         [][][]frontend.Variable
	CapContainer      [][]frontend.Variable
}

// Other types
type ProofObject struct {
	StatementValuesAtRandomPoint []Fp256 `json:"statement_values_at_random_point"`
}

type Config struct {
	WHIRConfigWitness            WHIRConfig `json:"whir_config_witness"`
	WHIRConfigHidingSpartan      WHIRConfig `json:"whir_config_hiding_spartan"`
	LogNumConstraints            int        `json:"log_num_constraints"`
	LogNumVariables              int        `json:"log_num_variables"`
	LogANumTerms                 int        `json:"log_a_num_terms"`
	IOPattern                    string     `json:"io_pattern"`
	Transcript                   []byte     `json:"transcript"`
	WitnessStatementEvaluations  []string   `json:"witness_statement_evaluations"`
	BlindingStatementEvaluations []string   `json:"blinding_statement_evaluations"`
}

type Hints struct {
	witnessHints      ZKHint
	spartanHidingHint ZKHint
}

type Hint struct {
	merklePaths []FullMultiPathWithCapping[Digest]
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
