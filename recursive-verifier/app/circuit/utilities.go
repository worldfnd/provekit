package circuit

import (
	"math/big"

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

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnarkNimue.Arthur, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	var protocolIDAndSessionID []frontend.Variable
	protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.ProtocolID[:32]))
	protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.ProtocolID[32:]))
	protocolIDAndSessionID = append(protocolIDAndSessionID, bytesToScalarLE(api, circuit.SessionID[:]))
	arthur, err := gnarkNimue.NewSkyscraperArthurWithProtocolID(api, sc, protocolIDAndSessionID, circuit.Transcript[:])
	if err != nil {
		return nil, nil, nil, err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, arthur, uapi, nil
}

// func runSumcheck(
// 	api frontend.API,
// 	arthur gnarkNimue.Arthur,
// 	lastEval frontend.Variable,
// 	foldingFactor int,
// 	polynomialDegree int,
// ) ([]frontend.Variable, frontend.Variable, error) {
// 	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
// 	foldingRandomness := make([]frontend.Variable, foldingFactor)
// 	foldingRandomnessTemp := make([]frontend.Variable, 1)

// 	for i := range foldingFactor {
// 		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
// 			return nil, nil, err
// 		}
// 		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
// 			return nil, nil, err
// 		}
// 		foldingRandomness[i] = foldingRandomnessTemp[0]
// 		sumcheckVal := api.Add(
// 			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{0})[0],
// 			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{1})[0],
// 		)
// 		api.AssertIsEqual(sumcheckVal, lastEval)
// 		lastEval = utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{foldingRandomness[i]})[0]
// 	}
// 	return foldingRandomness, lastEval, nil
// }

// func runZKSumcheck(
// 	api frontend.API,
// 	sc *skyscraper.Skyscraper,
// 	uapi *uints.BinaryField[uints.U64],
// 	circuit *Circuit,
// 	arthur gnarkNimue.Arthur,
// 	lastEval frontend.Variable,
// 	foldingFactor int,
// 	polynomialDegree int,
// 	whirParams WHIRParams,
// ) ([]frontend.Variable, frontend.Variable, error) {
// 	rootHash, batchingRandomness, initialOODQueries, initialOODAnswers, err := parseBatchedCommitment(arthur, whirParams)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	sumOfG, rhoRandomness, err := getZKSumcheckInitialValue(arthur)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	lastEval = api.Add(lastEval, api.Mul(sumOfG, rhoRandomness))

// 	foldingRandomness, lastEval, err := runSumcheck(api, arthur, lastEval, foldingFactor, polynomialDegree)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	lastEval, polynomialSums := unblindLastEval(api, arthur, lastEval, rhoRandomness)

// 	_, err = RunZKWhir(api, arthur, uapi, sc, circuit.HidingSpartanMerkle, circuit.HidingSpartanFirstRound, whirParams, [][]frontend.Variable{{polynomialSums[0]}, {polynomialSums[1]}}, circuit.HidingSpartanLinearStatementEvaluations, batchingRandomness, initialOODQueries, initialOODAnswers, rootHash)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	return foldingRandomness, lastEval, nil
// }

// func getZKSumcheckInitialValue(
// 	arthur gnarkNimue.Arthur,
// ) (frontend.Variable, frontend.Variable, error) {
// 	sumOfG := make([]frontend.Variable, 1)
// 	rhoRandomness := make([]frontend.Variable, 1)
// 	if err := arthur.FillNextScalars(sumOfG); err != nil {
// 		return nil, nil, err
// 	}
// 	if err := arthur.FillChallengeScalars(rhoRandomness); err != nil {
// 		return nil, nil, err
// 	}
// 	return sumOfG[0], rhoRandomness[0], nil
// }

// func unblindLastEval(
// 	api frontend.API,
// 	arthur gnarkNimue.Arthur,
// 	lastEval frontend.Variable,
// 	rhoRandomness frontend.Variable,
// ) (frontend.Variable, []frontend.Variable) {
// 	polynomialSums := make([]frontend.Variable, 2)
// 	if err := arthur.FillNextScalars(polynomialSums); err != nil {
// 		return 0, nil
// 	}

// 	lastEval = api.Sub(lastEval, api.Mul(polynomialSums[0], rhoRandomness))
// 	return lastEval, polynomialSums
// }

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
