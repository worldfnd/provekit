package circuit

import (
	"math/big"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// bytesToScalarLE interprets the first 32 bytes as a little-endian scalar (field element).
func bytesToScalarLE(api frontend.API, b []uints.U8) frontend.Variable {
	const wordSize = 32
	if len(b) < wordSize {
		return frontend.Variable(0)
	}
	out := frontend.Variable(0)
	curMul := big.NewInt(1)
	for i := 0; i < wordSize; i++ {
		out = api.Add(out, api.Mul(b[i].Val, curMul))
		curMul.Mul(curMul, big.NewInt(256))
	}
	return out
}

// func calculateEQ(api frontend.API, alphas []frontend.Variable, r []frontend.Variable) frontend.Variable {
// 	ans := frontend.Variable(1)
// 	for i, alpha := range alphas {
// 		ans = api.Mul(ans, api.Add(api.Mul(alpha, r[i]), api.Mul(api.Sub(frontend.Variable(1), alpha), api.Sub(frontend.Variable(1), r[i]))))
// 	}
// 	return ans
// }

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnarkNimue.Nimue, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	// var protocolIDAndSessionID []frontend.Variable
	// protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.ProtocolID[:32]))
	// protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.ProtocolID[32:]))
	// protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.SessionID[:]))
	nimue, err := gnarkNimue.NewSkyscraperNimue(api, sc, circuit.InitializationData, circuit.Transcript[:])
	if err != nil {
		return nil, nil, nil, err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, nimue, uapi, nil
}

func runSumcheck(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := range foldingFactor {
		if err := nimue.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := nimue.FillChallengeScalars(foldingRandomnessTemp); err != nil {
			return nil, nil, err
		}
		foldingRandomness[i] = foldingRandomnessTemp[0]
		sumcheckVal := api.Add(
			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{0})[0],
			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(sumcheckVal, lastEval)
		lastEval = utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{foldingRandomness[i]})[0]
	}
	return foldingRandomness, lastEval, nil
}

// runZKSumcheck replays the ZK Spartan sumcheck transcript.
// Returns (tRand, alpha, fAtAlpha, error) where:
//   - tRand: verifier randomness r (length m0)
//   - alpha: folding challenges from the sumcheck rounds (length m0)
//   - fAtAlpha: the unblinded final evaluation f(alpha)
func runZKSumcheck(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	uapi *uints.BinaryField[uints.U64],
	circuit *Circuit,
	nimue gnarkNimue.Nimue,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, []frontend.Variable, frontend.Variable, error) {
	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err := nimue.FillChallengeScalars(tRand)
	if err != nil {
		return nil, nil, nil, err
	}
	api.Println("tRand", tRand)

	sumOfG, rhoRandomness, err := getZKSumcheckInitialValue(nimue)
	if err != nil {
		return nil, nil, nil, err
	}
	api.Println("sumOfG", sumOfG)
	api.Println("rhoRandomness", rhoRandomness)

	lastEval = api.Add(lastEval, api.Mul(sumOfG, rhoRandomness))

	foldingRandomness, lastEval, err := runSumcheck(api, nimue, lastEval, foldingFactor, polynomialDegree)
	if err != nil {
		return nil, nil, nil, err
	}
	api.Println("foldingRandomness", foldingRandomness)
	api.Println("lastEval", lastEval)

	lastEval, polynomialSums := unblindLastEval(api, nimue, lastEval, rhoRandomness)
	api.Println("polynomialSums", polynomialSums)

	return tRand, foldingRandomness, lastEval, nil
}

func publicInputsHash(sc *skyscraper.Skyscraper, publicInputs PublicInputs) frontend.Variable {
	var expectedHash frontend.Variable
	switch len(publicInputs.Values) {
	case 0:
		expectedHash = frontend.Variable(0)
	case 1:
		expectedHash = sc.CompressV2(publicInputs.Values[0], frontend.Variable(0))
	default:
		expectedHash = publicInputs.Values[0]
		for i := 1; i < len(publicInputs.Values); i++ {
			expectedHash = sc.CompressV2(expectedHash, publicInputs.Values[i])
		}
	}
	return expectedHash
}

func publicInputsHashCheck(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	publicInputs PublicInputs,
) error {
	publicInputsHashBuf := make([]frontend.Variable, 1)
	if err := nimue.FillNextScalars(publicInputsHashBuf); err != nil {
		return err
	}

	expectedHash := publicInputsHash(sc, publicInputs)
	api.Println("publicInputsHashBuf", publicInputsHashBuf)
	api.Println("expectedHash", expectedHash)
	api.AssertIsEqual(publicInputsHashBuf[0], expectedHash)
	return nil
}

func getZKSumcheckInitialValue(
	nimue gnarkNimue.Nimue,
) (frontend.Variable, frontend.Variable, error) {
	sumOfG := make([]frontend.Variable, 1)
	rhoRandomness := make([]frontend.Variable, 1)
	if err := nimue.FillNextScalars(sumOfG); err != nil {
		return nil, nil, err
	}
	if err := nimue.FillChallengeScalars(rhoRandomness); err != nil {
		return nil, nil, err
	}
	return sumOfG[0], rhoRandomness[0], nil
}

func unblindLastEval(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	lastEval frontend.Variable,
	rhoRandomness frontend.Variable,
) (frontend.Variable, []frontend.Variable) {
	polynomialSums := make([]frontend.Variable, 1)
	if err := nimue.FillNextScalars(polynomialSums); err != nil {
		return 0, nil
	}

	lastEval = api.Sub(lastEval, api.Mul(polynomialSums[0], rhoRandomness))
	return lastEval, polynomialSums
}

func consumeFront[T any](slice *[]T) T {
	var zero T
	if len(*slice) == 0 {
		return zero
	}
	head := (*slice)[0]
	*slice = (*slice)[1:]
	return head
}

func consumeWhirData(whirConfig WHIRConfig, merkle_paths *[]FullMultiPath[KeccakDigest], stir_answers *[][][]Fp256) ZKHint {
	var zkHint ZKHint

	if len(*merkle_paths) > 0 && len(*stir_answers) > 0 {
		firstRoundMerklePath := consumeFront(merkle_paths)
		firstRoundStirAnswers := consumeFront(stir_answers)

		zkHint.firstRoundMerklePaths = FirstRoundHint{
			path: Hint{
				merklePaths: []FullMultiPath[KeccakDigest]{firstRoundMerklePath},
				stirAnswers: [][][]Fp256{firstRoundStirAnswers},
			},
			expectedStirAnswers: firstRoundStirAnswers,
		}
	}

	expectedRounds := whirConfig.NRounds

	var remainingMerklePaths []FullMultiPath[KeccakDigest]
	var remainingStirAnswers [][][]Fp256

	for i := 0; i < expectedRounds && len(*merkle_paths) > 0 && len(*stir_answers) > 0; i++ {
		remainingMerklePaths = append(remainingMerklePaths, consumeFront(merkle_paths))
		remainingStirAnswers = append(remainingStirAnswers, consumeFront(stir_answers))
	}

	zkHint.roundHints = Hint{
		merklePaths: remainingMerklePaths,
		stirAnswers: remainingStirAnswers,
	}

	return zkHint
}

// // consumeFirstRoundOnly consumes only the first round hint (no subsequent rounds)
// // Used for batch mode where each original commitment has its own first round
// func consumeFirstRoundOnly(merklePaths *[]FullMultiPath[KeccakDigest], stirAnswers *[][][]Fp256) FirstRoundHint {
// 	var hint FirstRoundHint

// 	if len(*merklePaths) > 0 && len(*stirAnswers) > 0 {
// 		firstRoundMerklePath := consumeFront(merklePaths)
// 		firstRoundStirAnswers := consumeFront(stirAnswers)

// 		hint = FirstRoundHint{
// 			path: Hint{
// 				merklePaths: []FullMultiPath[KeccakDigest]{firstRoundMerklePath},
// 				stirAnswers: [][][]Fp256{firstRoundStirAnswers},
// 			},
// 			expectedStirAnswers: firstRoundStirAnswers,
// 		}
// 	}

// 	return hint
// }

// // consumeWhirDataRoundsOnly consumes only the round hints (not first round)
// // Used for batched polynomial in batch mode
// func consumeWhirDataRoundsOnly(whirConfig WHIRConfig, merklePaths *[]FullMultiPath[KeccakDigest], stirAnswers *[][][]Fp256) ZKHint {
// 	var zkHint ZKHint

// 	expectedRounds := whirConfig.NRounds

// 	var remainingMerklePaths []FullMultiPath[KeccakDigest]
// 	var remainingStirAnswers [][][]Fp256

// 	for i := 0; i < expectedRounds && len(*merklePaths) > 0 && len(*stirAnswers) > 0; i++ {
// 		remainingMerklePaths = append(remainingMerklePaths, consumeFront(merklePaths))
// 		remainingStirAnswers = append(remainingStirAnswers, consumeFront(stirAnswers))
// 	}

// 	zkHint.roundHints = Hint{
// 		merklePaths: remainingMerklePaths,
// 		stirAnswers: remainingStirAnswers,
// 	}

// 	return zkHint
// }
