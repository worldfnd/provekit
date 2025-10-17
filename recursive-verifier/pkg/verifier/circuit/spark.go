package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"

	"reilabs/whir-verifier-circuit/pkg/verifier/merkle"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
	"reilabs/whir-verifier-circuit/pkg/verifier/whir"
)

func sparkSingleMatrix(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	matrix types.SPARKMatrixData,
	circuit *Circuit,
) error {
	claimedEvaluations := make([]frontend.Variable, 3)
	if err := arthur.FillNextScalars(claimedEvaluations); err != nil {
		return err
	}

	matrixCombinationRandomness := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(matrixCombinationRandomness); err != nil {
		return err
	}

	claimedValue := api.Add(
		claimedEvaluations[0],
		api.Mul(claimedEvaluations[1], matrixCombinationRandomness[0]),
		api.Mul(claimedEvaluations[2], matrixCombinationRandomness[0], matrixCombinationRandomness[0]),
	)

	sumcheckCommitment, err := merkle.ParseCommitment(arthur, matrix.WHIR5)
	if err != nil {
		return err
	}
	rowwiseCommitment, err := merkle.ParseCommitment(arthur, matrix.WHIR3)
	if err != nil {
		return err
	}
	colwiseCommitment, err := merkle.ParseCommitment(arthur, matrix.WHIR3)
	if err != nil {
		return err
	}

	rowFinalCommitment, err := merkle.ParseCommitment(arthur, circuit.WHIRRow)
	if err != nil {
		return err
	}
	colFinalCommitment, err := merkle.ParseCommitment(arthur, circuit.WHIRCol)
	if err != nil {
		return err
	}

	sparkSumcheckFoldingRandomness, sparkSumcheckLastEval, err := RunSumcheck(api, arthur, claimedValue, matrix.LogNumTerms, 4)
	if err != nil {
		return err
	}

	claimedVal := api.Add(
		matrix.SparkSumcheckLast[0],
		api.Mul(matrix.SparkSumcheckLast[1], matrixCombinationRandomness[0]),
		api.Mul(matrix.SparkSumcheckLast[2], matrixCombinationRandomness[0], matrixCombinationRandomness[0]),
	)

	api.AssertIsEqual(sparkSumcheckLastEval, api.Mul(claimedVal, matrix.SparkSumcheckLast[3], matrix.SparkSumcheckLast[4]))

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.SparkSumcheckMerkle, matrix.SparkSumcheckFirstRound, matrix.WHIR5, [][]frontend.Variable{{}, {}, {}, {}, {}}, []frontend.Variable{}, sumcheckCommitment,
		[][]frontend.Variable{{matrix.SparkSumcheckLast[0]}, {matrix.SparkSumcheckLast[1]}, {matrix.SparkSumcheckLast[2]}, {matrix.SparkSumcheckLast[3]}, {matrix.SparkSumcheckLast[4]}},
		[][]frontend.Variable{sparkSumcheckFoldingRandomness},
	)
	if err != nil {
		return err
	}

	tauGammaTemp := make([]frontend.Variable, 2)
	if err := arthur.FillChallengeScalars(tauGammaTemp); err != nil {
		return err
	}
	tau := tauGammaTemp[0]
	gamma := tauGammaTemp[1]

	gpaResult, err := gpaSumcheckVerifier(api, arthur, len(circuit.PointRow)+2)
	if err != nil {
		return err
	}

	claimedInit := gpaResult.claimedProducts[0]
	claimedFinal := gpaResult.claimedProducts[1]

	lastRandomness := gpaResult.randomness[0]
	evaluationRandomness := gpaResult.randomness[1:]

	addr := CalculateAdr(api, evaluationRandomness)
	mem := calculateEQ(api, circuit.PointRow, evaluationRandomness)
	initCntr := 0

	initOpening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), initCntr), tau)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.RowFinalMerkle, matrix.RowFinalMerkleFirstRound, circuit.WHIRRow, [][]frontend.Variable{{}}, []frontend.Variable{}, rowFinalCommitment,
		[][]frontend.Variable{{matrix.RowFinalCounter}},
		[][]frontend.Variable{evaluationRandomness},
	)
	if err != nil {
		return err
	}

	finalOpening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), matrix.RowFinalCounter), tau)
	evaluatedValue := api.Add(api.Mul(initOpening, api.Sub(1, lastRandomness)), api.Mul(finalOpening, lastRandomness))

	api.AssertIsEqual(gpaResult.lastSumcheckValue, evaluatedValue)

	gpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogNumTerms+2)
	if err != nil {
		return err
	}

	claimedRS := gpaResultRSWS.claimedProducts[0]
	claimedWS := gpaResultRSWS.claimedProducts[1]

	rswsLastRandomness := gpaResultRSWS.randomness[0]
	rswsEvaluationRandomness := gpaResultRSWS.randomness[1:]

	rsOpening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation), tau)
	wsOpening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation, 1), tau)

	rswsEvaluatedValue := api.Add(api.Mul(rsOpening, api.Sub(1, rswsLastRandomness)), api.Mul(wsOpening, rswsLastRandomness))

	api.AssertIsEqual(gpaResultRSWS.lastSumcheckValue, rswsEvaluatedValue)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.RowwiseMerkle, matrix.RowwiseMerkleFirstRound, matrix.WHIR3, [][]frontend.Variable{{}}, []frontend.Variable{}, rowwiseCommitment,
		[][]frontend.Variable{{matrix.RowRSAddressEvaluation}, {matrix.RowRSValueEvaluation}, {matrix.RowRSTimestampEvaluation}},
		[][]frontend.Variable{rswsEvaluationRandomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(claimedInit, claimedWS), api.Mul(claimedRS, claimedFinal))

	colwiseTauGammaTemp := make([]frontend.Variable, 2)
	if err := arthur.FillChallengeScalars(colwiseTauGammaTemp); err != nil {
		return err
	}
	colwiseTau := colwiseTauGammaTemp[0]
	colwiseGamma := colwiseTauGammaTemp[1]

	colwiseInitFinalGpaResult, err := gpaSumcheckVerifier(api, arthur, len(circuit.PointCol)-1+2)
	if err != nil {
		return err
	}

	colwiseClaimedInit := colwiseInitFinalGpaResult.claimedProducts[0]
	colwiseClaimedFinal := colwiseInitFinalGpaResult.claimedProducts[1]

	colwiseLastRandomness := colwiseInitFinalGpaResult.randomness[0]
	colwiseEvaluationRandomness := colwiseInitFinalGpaResult.randomness[1:]

	colwiseAddr := CalculateAdr(api, colwiseEvaluationRandomness)
	colwiseMem := api.Mul(calculateEQ(api, circuit.PointCol[1:], colwiseEvaluationRandomness), api.Sub(1, circuit.PointCol[0]))
	colwiseInitCntr := 0

	colwiseInitOpening := api.Sub(api.Add(api.Mul(colwiseAddr, colwiseGamma, colwiseGamma), api.Mul(colwiseMem, colwiseGamma), colwiseInitCntr), colwiseTau)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, circuit.SparkRLC.ColFinalMerkle, circuit.SparkRLC.ColFinalMerkleFirstRound, circuit.WHIRCol, [][]frontend.Variable{{}}, []frontend.Variable{}, colFinalCommitment,
		[][]frontend.Variable{{matrix.ColFinalCounter}},
		[][]frontend.Variable{colwiseEvaluationRandomness},
	)
	if err != nil {
		return err
	}

	colwiseFinalOpening := api.Sub(api.Add(api.Mul(colwiseAddr, colwiseGamma, colwiseGamma), api.Mul(colwiseMem, colwiseGamma), matrix.ColFinalCounter), colwiseTau)
	colwiseEvaluatedValue := api.Add(api.Mul(colwiseInitOpening, api.Sub(1, colwiseLastRandomness)), api.Mul(colwiseFinalOpening, colwiseLastRandomness))
	api.AssertIsEqual(colwiseInitFinalGpaResult.lastSumcheckValue, colwiseEvaluatedValue)

	colwiseGpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogNumTerms+2)
	if err != nil {
		return err
	}

	colwiseClaimedRS := colwiseGpaResultRSWS.claimedProducts[0]
	colwiseClaimedWS := colwiseGpaResultRSWS.claimedProducts[1]

	colwiseRswsLastRandomness := colwiseGpaResultRSWS.randomness[0]
	colwiseRswsEvaluationRandomness := colwiseGpaResultRSWS.randomness[1:]

	colwiseRsOpening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation), colwiseTau)
	colwiseWsOpening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation, 1), colwiseTau)

	colwiseRswsEvaluatedValue := api.Add(api.Mul(colwiseRsOpening, api.Sub(1, colwiseRswsLastRandomness)), api.Mul(colwiseWsOpening, colwiseRswsLastRandomness))

	api.AssertIsEqual(colwiseGpaResultRSWS.lastSumcheckValue, colwiseRswsEvaluatedValue)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.ColwiseMerkle, matrix.ColwiseMerkleFirstRound, matrix.WHIR3, [][]frontend.Variable{{}}, []frontend.Variable{}, colwiseCommitment,
		[][]frontend.Variable{{matrix.ColRSAddressEvaluation}, {matrix.ColRSValueEvaluation}, {matrix.ColRSTimestampEvaluation}},
		[][]frontend.Variable{colwiseRswsEvaluationRandomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(colwiseClaimedInit, colwiseClaimedWS), api.Mul(colwiseClaimedRS, colwiseClaimedFinal))

	return nil
}
