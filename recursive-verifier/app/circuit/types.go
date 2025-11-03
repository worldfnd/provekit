package circuit

import (
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
	WHIRConfigWitness            WHIRConfig `json:"whir_config_witness"`
	WHIRConfigHidingSpartan      WHIRConfig `json:"whir_config_hiding_spartan"`
	LogNumConstraints            int        `json:"log_num_constraints"`
	LogNumVariables              int        `json:"log_num_variables"`
	LogANumTerms                 int        `json:"log_a_num_terms"`
	IOPattern                    string     `json:"io_pattern"`
	Transcript                   []byte     `json:"transcript"`
	TranscriptLen                int        `json:"transcript_len"`
	WitnessStatementEvaluations  []string   `json:"witness_statement_evaluations"`
	BlindingStatementEvaluations []string   `json:"blinding_statement_evaluations"`
}

type Hints struct {
	pointRow []Fp256
	pointCol []Fp256

	witnessHints      ZKHint
	spartanHidingHint ZKHint

	SparkHints SparkMatrixHints
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

type SparkConfig struct {
	Transcript  []byte     `json:"transcript"`
	IOPattern   string     `json:"io_pattern"`
	WHIRRow     WHIRConfig `json:"whir_row"`
	WHIRCol     WHIRConfig `json:"whir_col"`
	WHIR1       WHIRConfig `json:"whir_1batched"`
	WHIR2       WHIRConfig `json:"whir_2batched"`
	WHIR4       WHIRConfig `json:"whir_4batched"`
	LogNumTerms int        `json:"log_num_terms"`
}

type Commitment struct {
	rootHash           frontend.Variable
	batchingRandomness frontend.Variable
	initialOODQueries  []frontend.Variable
	initialOODAnswers  [][]frontend.Variable
}

type SPARKMatrixData struct {
	Claimed frontend.Variable

	WHIR1       WHIRParams
	WHIR2       WHIRParams
	WHIR4       WHIRParams
	LogNumTerms int

	SparkSumcheckLast []frontend.Variable

	RowFinalCounter          frontend.Variable
	RowRSAddressEvaluation   frontend.Variable
	RowRSValueEvaluation     frontend.Variable
	RowRSTimestampEvaluation frontend.Variable

	ColFinalCounter          frontend.Variable
	ColRSAddressEvaluation   frontend.Variable
	ColRSValueEvaluation     frontend.Variable
	ColRSTimestampEvaluation frontend.Variable

	EvaluesSumcheckMerkleFirstRound      Merkle
	EvaluesSumcheckMerkleRemainingRounds Merkle

	ValsMerkleFirstRound      Merkle
	ValsMerkleRemainingRounds Merkle

	RSWSMerkleFirstRound      Merkle
	RSWSMerkleRemainingRounds Merkle

	EvaluesRSWSMerkleFirstRound      Merkle
	EvaluesRSWSMerkleRemainingRounds Merkle

	RowFinalMerkleFirstRound      Merkle
	RowFinalMerkleRemainingRounds Merkle

	ColFinalMerkleFirstRound      Merkle
	ColFinalMerkleRemainingRounds Merkle
}

type SparkMatrixHints struct {
	claimed Fp256

	evaluesSumcheck ZKHint
	vals            ZKHint
	rsws            ZKHint
	evaluesRSWS     ZKHint
	rowFinal        ZKHint
	colFinal        ZKHint

	sparkClaimedEvaluations []Fp256

	rowFinalCounter          Fp256
	rowRSAddressEvaluation   Fp256
	rowRSValueEvaluation     Fp256
	rowRSTimestampEvaluation Fp256

	colFinalCounter          Fp256
	colRSAddressEvaluation   Fp256
	colRSValueEvaluation     Fp256
	colRSTimestampEvaluation Fp256
}
