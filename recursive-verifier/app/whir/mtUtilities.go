package whir

import (
	"fmt"
	"math/big"
	"math/bits"
	"reilabs/whir-verifier-circuit/app/typeConverters"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// initialSumcheck mirrors the Rust WHIR verifier's initial sumcheck phase.
// The sum has already been computed by the caller (theSum). This function
// runs the sumcheck rounds to reduce the claim, and stores the OOD queries
// and RLC coefficients for the final W polynomial verification.
func initialSumcheck(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	theSum frontend.Variable,
	oodPoints []frontend.Variable,
	oodsRlcCoeffs []frontend.Variable,
	initialFormRlcCoeffs []frontend.Variable,
	whirParams WHIRParams,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {

	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, theSum, nimue, whirParams.FoldingFactorArray[0])
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	combinedRlcCoeffs := make([]frontend.Variable, len(initialFormRlcCoeffs)+len(oodsRlcCoeffs))
	copy(combinedRlcCoeffs, initialFormRlcCoeffs)
	copy(combinedRlcCoeffs[len(initialFormRlcCoeffs):], oodsRlcCoeffs)

	return InitialSumcheckData{
		InitialOODQueries:            oodPoints,
		InitialCombinationRandomness: combinedRlcCoeffs,
	}, lastEval, initialSumcheckFoldingRandomness, nil
}

// runWhirSumcheckRounds mirrors the Rust WHIR quadratic sumcheck verifier
// (whir/src/protocols/sumcheck.rs Config::verify).
//
// Each round the prover sends two coefficients (c0, c2) of a quadratic
// polynomial P(x) = c0 + c1·x + c2·x². The third coefficient c1 is derived
// from the sum constraint P(0) + P(1) = sum, giving c1 = sum − 2·c0 − c2.
// After squeezing a folding challenge r, the sum is updated to P(r).
func runWhirSumcheckRounds(
	api frontend.API,
	sum frontend.Variable,
	nimue gnarkNimue.Nimue,
	numRounds int,
) ([]frontend.Variable, frontend.Variable, error) {
	foldingRandomness := make([]frontend.Variable, numRounds)

	for i := range numRounds {
		coeffs := make([]frontend.Variable, 2)
		if err := nimue.FillNextScalars(coeffs); err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d: %w", i, err)
		}
		c0 := coeffs[0]
		c2 := coeffs[1]
		api.Println("c0", c0)
		api.Println("c2", c2)

		c1 := api.Sub(sum, api.Add(api.Add(c0, c0), c2))

		rBuf := make([]frontend.Variable, 1)
		if err := nimue.FillChallengeScalars(rBuf); err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d challenge: %w", i, err)
		}
		api.Println("rBuf", rBuf[0])
		foldingRandomness[i] = rBuf[0]

		r := foldingRandomness[i]
		sum = api.Add(api.Mul(api.Add(api.Mul(c2, r), c1), r), c0)
	}
	return foldingRandomness, sum, nil
}

func getStirChallenges(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / foldingFactorPower
	domainSizeBytes := (bits.Len(uint(foldedDomainSize*2-1)) - 1 + 7) / 8
	api.Println("domainSizeBytes", domainSizeBytes)
	api.Println("numQueries", numQueries)
	stirQueries := make([]uints.U8, domainSizeBytes*numQueries)
	if err := nimue.FillChallengeBytes(stirQueries); err != nil {
		return nil, err
	}
	api.Println("stirQueries", stirQueries)
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

func generateEmptyMainRoundData(circuit WHIRParams) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
	}
}

// ExponentVar computes base^exp using square-and-multiply with a field element exponent.
// numBits determines how many bits of exp to consider.
func ExponentVar(api frontend.API, base frontend.Variable, exp frontend.Variable, numBits int) frontend.Variable {
	expBits := api.ToBinary(exp, numBits)
	output := frontend.Variable(1)
	multiply := base
	for i := range expBits {
		output = api.Select(expBits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

// RunPoW executes a proof-of-work challenge if the difficulty is greater than zero.
func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, nimue gnarkNimue.Nimue, difficulty int) error {
	if difficulty > 0 {
		_, _, err := PoW(api, sc, nimue, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}

// PoW performs a proof-of-work verification using nimue transcript and Skyscraper hash.
func PoW(api frontend.API, sc *skyscraper.Skyscraper, nimue gnarkNimue.Nimue, difficulty int) ([]uints.U8, []uints.U8, error) {
	challenge := make([]uints.U8, 32)
	if err := nimue.FillChallengeBytes(challenge); err != nil {
		return nil, nil, err
	}
	api.Println("challenge", challenge)
	nonce := make([]uints.U8, 8)
	if err := nimue.FillNextBytes(nonce); err != nil {
		return nil, nil, err
	}
	api.Println("nonce", nonce)
	challengeFieldElement := typeConverters.LittleEndianFromUints(api, challenge)
	nonceFieldElement := typeConverters.LittleEndianFromUints(api, nonce)
	err := CheckPoW(api, sc, challengeFieldElement, nonceFieldElement, difficulty)
	if err != nil {
		return nil, nil, err
	}
	return challenge, nonce, nil
}

// CheckPoW verifies a proof-of-work using Skyscraper hash.
// Compares only the first limb (low 64 bits) of the hash against the first
// limb of the threshold (modulus >> difficulty).
func CheckPoW(api frontend.API, sc *skyscraper.Skyscraper, challenge frontend.Variable, nonce frontend.Variable, difficulty int) error {
	maxUint64, _ := new(big.Int).SetString("18446744073709551615", 10)
	api.AssertIsLessOrEqual(nonce, maxUint64)

	hash := sc.CompressV2(challenge, nonce)

	// Decompose hash into 254 bits (BN254 field element size)
	hashBits := api.ToBinary(hash, 254)

	// Reconstruct the first limb (low 64 bits) from bits
	firstLimb := api.FromBinary(hashBits[:64]...)

	// Compute threshold first limb: (modulus >> difficulty) & 0xFFFFFFFFFFFFFFFF
	modulus, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	threshold := new(big.Int).Rsh(modulus, uint(difficulty))
	threshold.And(threshold, maxUint64)

	api.Println("firstLimb, threshold", firstLimb, threshold)
	api.AssertIsLessOrEqual(firstLimb, threshold)
	return nil
}
