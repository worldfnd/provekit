package whir

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// SoundnessType defines the soundness guarantee for the proof system.
type SoundnessType int

const (
	UniqueDecoding SoundnessType = iota
	ProvableList
	ConjectureList
)

// FoldingFactor defines the folding strategy per round.
type FoldingFactor struct {
	// Constant: same factor every round. ConstantFromSecondRound: first round
	// uses FirstRound, subsequent rounds use Factor.
	Factor        int
	FirstRound    int // only used when VariableFirst is true
	VariableFirst bool
}

// ConstantFoldingFactor creates a FoldingFactor with the same value every round.
func ConstantFoldingFactor(factor int) FoldingFactor {
	return FoldingFactor{Factor: factor}
}

// ConstantFromSecondRoundFoldingFactor creates a FoldingFactor where the first
// round uses firstRound and subsequent rounds use factor.
func ConstantFromSecondRoundFoldingFactor(firstRound, factor int) FoldingFactor {
	return FoldingFactor{Factor: factor, FirstRound: firstRound, VariableFirst: true}
}

// AtRound returns the folding factor for the given round index.
func (ff FoldingFactor) AtRound(round int) int {
	if ff.VariableFirst && round == 0 {
		return ff.FirstRound
	}
	return ff.Factor
}

// ComputeNumberOfRounds returns (numRounds, finalSumcheckRounds).
func (ff FoldingFactor) ComputeNumberOfRounds(numVariables int) (int, int) {
	if ff.VariableFirst {
		nvExceptFirst := numVariables - ff.FirstRound
		if nvExceptFirst < ff.Factor {
			return 0, nvExceptFirst
		}
		finalSumcheckRounds := nvExceptFirst % ff.Factor
		return (nvExceptFirst - finalSumcheckRounds) / ff.Factor, finalSumcheckRounds
	}
	finalSumcheckRounds := numVariables % ff.Factor
	return (numVariables-finalSumcheckRounds)/ff.Factor - 1, finalSumcheckRounds
}

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
	Config                               ProtocolConfig
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
	InitialInDomainSamples               int
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


// ComputeWhirProofFrs returns the exact number of field elements consumed from
// the WHIR transcript verifier (narg string) during ReceiveCommitment + VerifyWhir.
// This traces every Read/ReadVector call on the transcript deterministically.
func ComputeWhirProofFrs(params WHIRParams) int {
	count := 0

	// ReceiveCommitment: root hash + OOD answers
	count += 1 + params.CommittmentOODSamples*params.BatchSize

	// Initial sumcheck: runWhirSumcheckRounds(FoldingFactorArray[0])
	// Each round reads c0, c2 = 2 elements
	count += 2 * params.FoldingFactorArray[0]

	// Main rounds
	for r := range params.ParamNRounds {
		count += 1                                   // root hash
		count += params.RoundParametersOODSamples[r] // OOD answers
		if params.PowBits[r] > 0 {
			count += 1 // PoW nonce
		}
		count += 2 * params.FoldingFactorArray[r+1] // round sumcheck
	}

	// Final vector
	count += 1 << params.FinalSumcheckRounds

	// Final PoW
	if params.FinalPowBits > 0 {
		count += 1
	}

	// Final sumcheck
	count += 2 * params.FinalSumcheckRounds

	// Final folding PoW
	if params.FinalFoldingPowBits > 0 {
		count += 1
	}

	return count
}

// ComputeWhirHintBytes returns the total byte length of the WHIR hint stream,
// computed deterministically from params. Each Vec block is 8 (count prefix) + count*32,
// each Hash block is 32 bytes.
func ComputeWhirHintBytes(params WHIRParams, numStatements int) int {
	bytes := 0
	domainSize := params.DomainSize

	// 1. Initial leaves Vec: numQueries[0] * batchSize * (1 << ff[0])
	initialVecCount := params.RoundParametersNumOfQueries[0] * params.BatchSize * (1 << params.FoldingFactorArray[0])
	bytes += 8 + initialVecCount*32

	for r := range params.ParamNRounds {
		if r == 0 {
			// Round 0: Merkle paths on initial leaves (no new Vec)
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[0]))) - 1
			bytes += params.RoundParametersNumOfQueries[0] * treeHeight * 32
		} else {
			// Round r>0: leaves Vec + Merkle paths
			vecCount := params.RoundParametersNumOfQueries[r] * (1 << params.FoldingFactorArray[r])
			bytes += 8 + vecCount*32
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[r]))) - 1
			bytes += params.RoundParametersNumOfQueries[r] * treeHeight * 32
		}
		domainSize /= 2
	}

	// Final leaves Vec + Merkle paths
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	if params.ParamNRounds > 0 {
		finalVecCount := params.FinalQueries * (1 << lastFoldingFactor)
		bytes += 8 + finalVecCount*32
	} else {
		finalVecCount := params.FinalQueries * params.BatchSize * (1 << lastFoldingFactor)
		bytes += 8 + finalVecCount*32
	}
	finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
	bytes += params.FinalQueries * finalTreeHeight * 32

	// Deferred evals Vec
	bytes += 8 + numStatements*32

	return bytes
}

// ComputeWhirBytes returns the total byte length of the WHIR proof portion
// (narg string + hints), computed deterministically from params.
func ComputeWhirBytes(params WHIRParams, numStatements int) int {
	nargBytes := 8 + ComputeWhirProofFrs(params)*32
	hintBytes := 8 + ComputeWhirHintBytes(params, numStatements)
	return nargBytes + hintBytes
}

// ComputeHintBlockTypes returns the block type sequence (0=Vec, 1=Hash)
// for all HintReader calls in VerifyWhir, derived deterministically from params.
// This allows pre-computing byte offsets into the hint stream.
func ComputeHintBlockTypes(params WHIRParams) []int {
	var types []int
	domainSize := params.DomainSize

	// 1. Initial leaves: readLeavesFromHints → 1 Vec
	types = append(types, 0)

	for r := range params.ParamNRounds {
		if r == 0 {
			// Round 0: verifyMerklePaths on initialLeaves (no new ReadVec)
			numQueries := params.RoundParametersNumOfQueries[0]
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[0]))) - 1
			for range numQueries * treeHeight {
				types = append(types, 1)
			}
		} else {
			// Round r>0: readLeavesFromHints → 1 Vec
			types = append(types, 0)
			// verifyMerklePaths on roundLeaves
			numQueries := params.RoundParametersNumOfQueries[r]
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[r]))) - 1
			for range numQueries * treeHeight {
				types = append(types, 1)
			}
		}
		domainSize /= 2
	}

	// Final leaves + Merkle paths
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	types = append(types, 0) // readLeavesFromHints → 1 Vec
	finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
	for range params.FinalQueries * finalTreeHeight {
		types = append(types, 1)
	}

	// Deferred evals: hr.ReadVec → 1 Vec
	types = append(types, 0)

	return types
}
