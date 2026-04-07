package circuit

import (
	"reilabs/whir-verifier-circuit/app/utilities"
	"reilabs/whir-verifier-circuit/app/whir"

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

// WHIR specific types
type WHIRConfig struct {
	NRounds                int    `json:"n_rounds"`
	Rate                   int    `json:"rate"`
	NVars                  int    `json:"n_vars"`
	FoldingFactor          []int  `json:"folding_factor"`
	OODSamples             []int  `json:"ood_samples"`
	NumQueries             []int  `json:"num_queries"`
	PowBits                []int  `json:"pow_bits"`
	FinalQueries           int    `json:"final_queries"`
	FinalPowBits           int    `json:"final_pow_bits"`
	FinalFoldingPowBits    int    `json:"final_folding_pow_bits"`
	DomainGenerator        string `json:"domain_generator"`
	BatchSize              int    `json:"batch_size"`
	InitialInDomainSamples int    `json:"initial_in_domain_samples"` // initial_committer.in_domain_samples (num queries for zkWHIR in-domain verification)
}

// WHIRParams is an alias for whir.WHIRParams to avoid duplicate struct definitions.
type WHIRParams = whir.WHIRParams

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
type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][]frontend.Variable
	AuthPaths         [][][]frontend.Variable
}

// Config matches the Rust GnarkConfig struct.
// narg_string + hints are the spongefish proof buffers.
// protocol_id is SHA3-512(CBOR(WhirR1CSScheme)); session_id is optional (default zero) for domain separation.
type Config struct {
	BlindedCommitmentWhirConfig  WHIRConfig   `json:"blinded_commitment_whir_config"`
	BlindingCommitmentWhirConfig WHIRConfig   `json:"blinding_commitment_whir_config"`
	LogNumConstraints            int          `json:"log_num_constraints"`
	LogNumVariables              int          `json:"log_num_variables"`
	LogANumTerms                 int          `json:"log_a_num_terms"`
	NargString                   []byte       `json:"narg_string"`
	NargStringLen                int          `json:"narg_string_len"`
	Hints                        []byte       `json:"hints"`
	HintsLen                     int          `json:"hints_len"`
	ProtocolID                   []byte       `json:"protocol_id"`
	SessionID                    []byte       `json:"session_id"`
	NumChallenges                int          `json:"num_challenges"`
	W1Size                       int          `json:"w1_size"`
	PublicInputs                 PublicInputs `json:"public_inputs"`
}

type Hint struct {
	merklePaths []FullMultiPath[Digest]
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
