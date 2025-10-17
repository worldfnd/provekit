package types

// Config captures the verifier configuration for the main circuit.
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

// Hints groups transcripts and matrix hints used during verification.
type Hints struct {
	PointRow []Fp256
	PointCol []Fp256

	WitnessHints      ZKHint
	SpartanHidingHint ZKHint

	AHints SparkMatrixHints
	BHints SparkMatrixHints
	CHints SparkMatrixHints
}

// Hint bundles Merkle paths and STIR answers.
type Hint struct {
	MerklePaths []FullMultiPath[KeccakDigest]
	StirAnswers [][][]Fp256
}

// FirstRoundHint captures data for the first round of the transcript.
type FirstRoundHint struct {
	Path                Hint
	ExpectedStirAnswers [][]Fp256
}

// ZKHint stores zero-knowledge hints for a WHIR instance.
type ZKHint struct {
	FirstRoundMerklePaths FirstRoundHint
	RoundHints            Hint
}

// ClaimedEvaluations wraps the claimed polynomial sums.
type ClaimedEvaluations struct {
	FSums []Fp256
	GSums []Fp256
}
