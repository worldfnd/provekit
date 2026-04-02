package circuit

import (
	"math/big"
	"math/bits"

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

func getStirChallenges(
	api frontend.API,
	arthur gnarkNimue.Nimue,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / foldingFactorPower
	domainSizeBytes := (bits.Len(uint(foldedDomainSize*2-1)) - 1 + 7) / 8

	stirQueries := make([]uints.U8, domainSizeBytes*numQueries)
	if err := arthur.FillChallengeBytes(stirQueries); err != nil {
		return nil, err
	}

	bitLength := bits.Len(uint(foldedDomainSize)) - 1

	indexes := make([]frontend.Variable, numQueries)
	for i := range numQueries {
		var value frontend.Variable = 0
		for j := range domainSizeBytes {
			value = api.Add(stirQueries[j+i*domainSizeBytes].Val, api.Mul(value, 256))
		}

		bitsOfValue := api.ToBinary(value)
		indexes[i] = api.FromBinary(bitsOfValue[:bitLength]...)
	}

	return indexes, nil
}
