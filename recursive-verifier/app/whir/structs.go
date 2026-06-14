package whir

import (
	"github.com/consensys/gnark/frontend"
)

type ParsedCommitment struct {
	Root       frontend.Variable
	OodPoints  []frontend.Variable
	OodAnswers []frontend.Variable // flat: out_domain_samples * num_vectors
}

type Statement struct {
	Constraints []MLConstraint
	NVars       int
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
	CommitmentOODSamples                 int
	FinalSumcheckRounds                  int
	MVParamsNumberOfVariables            int
	BatchSize                            int
	InitialInDomainSamples               int
	// OmegaFull is the generator of the full NTT domain (order = DomainSize).
	// Used to compute gamma points for batched_h_claims verification.
	OmegaFull frontend.Variable
	// Zeta = OmegaFull^(DomainSize/interleavingDepth), the interleaving coset generator.
	Zeta frontend.Variable
}

type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

type MLConstraint struct {
	Point      []frontend.Variable
	Evaluation frontend.Variable
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

// FinalClaimCircuit mirrors the Rust FinalClaim<F> for the gnark circuit.
// The caller must verify: LinearFormRLC == Σ(RLCCoefficients[i] * weight_i.mle_evaluate(EvaluationPoint))
type FinalClaimCircuit struct {
	EvaluationPoint []frontend.Variable
	RLCCoefficients []frontend.Variable
	LinearFormRLC   frontend.Variable
}

// VerifyResult bundles all outputs from VerifyWhir.
type VerifyResult struct {
	TotalFoldingRandomness []frontend.Variable
	FinalClaim             FinalClaimCircuit
}

// RoundMerkleEntry holds the Merkle proof data for one round of WHIR opening.
type RoundMerkleEntry struct {
	// Leaf values (submatrix): [query_idx][fold_element_idx]
	Leaves [][]frontend.Variable
	// Leaf sibling hashes for the Merkle proof: [query_idx]
	SiblingHashes []frontend.Variable
	// Auth path hashes for the Merkle proof: [query_idx][level]
	AuthPaths [][]frontend.Variable
	// Leaf indexes in the folded domain: [query_idx]
	LeafIndexes []frontend.Variable
}

// WhirMerkleData holds all Merkle proof data for a single VerifyWhir call.
// Rounds[0..nRounds-1] correspond to main round openings;
// Rounds[nRounds] is the final round opening.
type WhirMerkleData struct {
	Rounds []RoundMerkleEntry
}
