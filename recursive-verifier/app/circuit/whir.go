package circuit

import (
	"math/big"

	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
)

// NewWhirParams creates a new WHIRParams instance from the given configuration.
// It processes the folding factors and calculates domain sizes based on the provided config.
// bn254TwoAdicRootOfUnity is the primitive 2^28-th root of unity for BN254 Fr.
// This matches arkworks bn254::Fr::TWO_ADIC_ROOT_OF_UNITY.
var bn254TwoAdicRootOfUnity, _ = new(big.Int).SetString(
	"19103219067921713944291392827692070036145651957329286315305642004821462161904", 10)

const bn254TwoAdicity = 28

// computeNTTGenerator computes the primitive root of unity of order `domainSize`
// for the BN254 scalar field. domainSize must be a power of two <= 2^28.
func computeNTTGenerator(domainSize int) *big.Int {
	// generator(N) = two_adic_root ^ (2^28 / N)
	exp := new(big.Int).SetUint64(uint64(1 << bn254TwoAdicity / domainSize))
	return new(big.Int).Exp(bn254TwoAdicRootOfUnity, exp, bn254Modulus)
}

func NewWhirParams(cfg WHIRConfig) WHIRParams {
	startingDomainGen, _ := new(big.Int).SetString(cfg.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.NVars
	var foldingFactor []int
	var finalSumcheckRounds int

	if len(cfg.FoldingFactor) > 1 {
		foldingFactor = append(cfg.FoldingFactor, cfg.FoldingFactor[len(cfg.FoldingFactor)-1])
		finalSumcheckRounds = mvParamsNumberOfVariables % foldingFactor[len(foldingFactor)-1]
	} else {
		foldingFactor = []int{4}
		finalSumcheckRounds = mvParamsNumberOfVariables % 4
	}
	domainSize := (2 << mvParamsNumberOfVariables) * (1 << cfg.Rate) / 2
	interleavingDepth := 1 << foldingFactor[0]

	// Compute omega_full (generator of full domain of size DomainSize) and
	// zeta (interleaving coset generator = omega_full^codeword_length).
	omegaFull := computeNTTGenerator(domainSize)
	codewordLength := domainSize / interleavingDepth
	zeta := new(big.Int).Exp(omegaFull, big.NewInt(int64(codewordLength)), bn254Modulus)

	return WHIRParams{
		ParamNRounds:                         cfg.NRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            cfg.OODSamples,
		RoundParametersNumOfQueries:          cfg.NumQueries,
		PowBits:                              cfg.PowBits,
		FinalQueries:                         cfg.FinalQueries,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: *startingDomainGen,
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		BatchSize:                            cfg.BatchSize,
		InitialInDomainSamples:               cfg.InitialInDomainSamples,
		OmegaFull:                            *omegaFull,
		Zeta:                                 *zeta,
	}
}

// GenerateStirChallengePoints generates the stir challenge points for the given parameters.
// It calculates the folding factor power and generates the stir challenges for the given leaf indexes.
func GenerateStirChallengePoints(
	api frontend.API,
	arthur gnarkNimue.Nimue,
	NQueries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingFactorPower := 1 << foldingFactor
	finalIndexes, err := getStirChallenges(api, arthur, NQueries, domainSize, foldingFactorPower)
	if err != nil {
		return nil, err
	}

	err = utilities.IsEqual(api, uapi, finalIndexes, leafIndexes)
	if err != nil {
		return nil, err
	}

	finalRandomnessPoints := make([]frontend.Variable, len(leafIndexes))

	for index := range leafIndexes {
		finalRandomnessPoints[index] = utilities.Exponent(api, uapi, expDomainGenerator, leafIndexes[index])
	}

	return finalRandomnessPoints, nil
}

// GenerateCombinationRandomness generates the combination randomness for the given parameters.
// It generates a random scalar and expands it to the required length.
func GenerateCombinationRandomness(api frontend.API, arthur gnarkNimue.Nimue, randomnessLength int) ([]frontend.Variable, error) {
	combRandomnessGen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(combRandomnessGen); err != nil {
		return nil, err
	}

	combinationRandomness := utilities.ExpandRandomness(api, combRandomnessGen[0], randomnessLength)
	return combinationRandomness, nil
}
