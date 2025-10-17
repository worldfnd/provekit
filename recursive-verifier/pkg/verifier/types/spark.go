package types

import (
	"github.com/consensys/gnark/frontend"
)

// SparkConfig describes the SPARK transcript inputs.
type SparkConfig struct {
	IOPattern   string     `json:"io_pattern"`
	Transcript  []byte     `json:"transcript"`
	WHIR3       WHIRConfig `json:"whir_3batched"`
	WHIR5       WHIRConfig `json:"whir_5batched"`
	WHIRRow     WHIRConfig `json:"whir_row"`
	WHIRCol     WHIRConfig `json:"whir_col"`
	LogNumTerms int        `json:"log_num_terms"`
}

// SparkCommitment holds commitments opened during SPARK verification.
type SparkCommitment struct {
	RootHash           frontend.Variable
	BatchingRandomness frontend.Variable
	InitialOODQueries  []frontend.Variable
	InitialOODAnswers  [][]frontend.Variable
}

// SPARKMatrixData collects row/column commitments and claimed values.
type SPARKMatrixData struct {
	Claimed frontend.Variable

	WHIR3       WHIRParams
	WHIR5       WHIRParams
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

	SparkSumcheckFirstRound Merkle
	SparkSumcheckMerkle     Merkle

	RowFinalMerkleFirstRound Merkle
	RowFinalMerkle           Merkle

	RowwiseMerkleFirstRound Merkle
	RowwiseMerkle           Merkle

	ColFinalMerkleFirstRound Merkle
	ColFinalMerkle           Merkle

	ColwiseMerkleFirstRound Merkle
	ColwiseMerkle           Merkle
}

// SparkMatrixHints contains SPARK-specific hints extracted from transcripts.
type SparkMatrixHints struct {
	Claimed Fp256

	SparkSumcheckData  ZKHint
	RowFinalMerkle     ZKHint
	RowwiseSparkMerkle ZKHint
	ColFinalMerkle     ZKHint
	ColwiseSparkMerkle ZKHint

	SparkClaimedEvaluations []Fp256

	RowFinalCounter          Fp256
	RowRSAddressEvaluation   Fp256
	RowRSValueEvaluation     Fp256
	RowRSTimestampEvaluation Fp256

	ColFinalCounter          Fp256
	ColRSAddressEvaluation   Fp256
	ColRSValueEvaluation     Fp256
	ColRSTimestampEvaluation Fp256
}
