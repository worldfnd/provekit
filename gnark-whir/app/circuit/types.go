package circuit

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
	WHIRConfigCol     WHIRConfig `json:"whir_config_col"`
	LogNumConstraints int        `json:"log_num_constraints"`
	LogNumVariables   int        `json:"log_num_variables"`
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
	ColHints Hint
}

type Hint struct {
	MerklePaths []MultiPath[KeccakDigest]
	StirAnswers [][][]Fp256
}
