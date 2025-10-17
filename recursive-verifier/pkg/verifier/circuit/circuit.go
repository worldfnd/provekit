package circuit

import (
	"reilabs/whir-verifier-circuit/pkg/encoding/typeconv"
	"reilabs/whir-verifier-circuit/pkg/verifier/merkle"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
	"reilabs/whir-verifier-circuit/pkg/verifier/whir"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type Circuit struct {
	WitnessLinearStatementEvaluations       []frontend.Variable
	HidingSpartanLinearStatementEvaluations []frontend.Variable
	LogNumConstraints                       int
	LogNumVariables                         int
	LogANumTerms                            int
	WitnessClaimedEvaluations               []frontend.Variable
	WitnessBlindingEvaluations              []frontend.Variable
	HidingSpartanFirstRound                 types.Merkle
	HidingSpartanMerkle                     types.Merkle
	WitnessMerkle                           types.Merkle
	WitnessFirstRound                       types.Merkle
	WHIRParamsWitness                       types.WHIRParams
	WHIRParamsHidingSpartan                 types.WHIRParams

	MatrixA []types.MatrixCell
	MatrixB []types.MatrixCell
	MatrixC []types.MatrixCell

	IO              []byte
	UseSpark        bool
	SPARKTranscript []uints.U8

	SPARKIO    []byte
	Transcript []uints.U8

	WHIRRow types.WHIRParams
	WHIRCol types.WHIRParams

	PointRow []frontend.Variable
	PointCol []frontend.Variable

	SparkRLC types.SPARKMatrixData
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	spartanCommitment, err := merkle.ParseCommitment(arthur, circuit.WHIRParamsWitness)
	if err != nil {
		return err
	}

	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(tRand)
	if err != nil {
		return err
	}

	spartanSumcheckRand, spartanSumcheckLastValue, err := RunZKSumcheck(api, sc, uapi, circuit, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4, circuit.WHIRParamsHidingSpartan)
	if err != nil {
		return err
	}

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, circuit.WitnessMerkle, circuit.WitnessFirstRound, circuit.WHIRParamsWitness, [][]frontend.Variable{circuit.WitnessClaimedEvaluations, circuit.WitnessBlindingEvaluations}, circuit.WitnessLinearStatementEvaluations, spartanCommitment,
		[][]frontend.Variable{{}, {}},
		[][]frontend.Variable{},
	)
	if err != nil {
		return err
	}

	x := api.Mul(api.Sub(api.Mul(circuit.WitnessClaimedEvaluations[0], circuit.WitnessClaimedEvaluations[1]), circuit.WitnessClaimedEvaluations[2]), calculateEQ(api, spartanSumcheckRand, tRand))
	api.AssertIsEqual(spartanSumcheckLastValue, x)

	return nil
}

func parseClaimedEvaluations(claimedEvaluations types.ClaimedEvaluations, isContainer bool) ([]frontend.Variable, []frontend.Variable) {
	fSums := make([]frontend.Variable, len(claimedEvaluations.FSums))
	gSums := make([]frontend.Variable, len(claimedEvaluations.GSums))

	if !isContainer {
		for i := range claimedEvaluations.FSums {
			fSums[i] = typeconv.LimbsToBigIntMod(claimedEvaluations.FSums[i].Limbs)
			gSums[i] = typeconv.LimbsToBigIntMod(claimedEvaluations.GSums[i].Limbs)
		}
	}

	return fSums, gSums
}

func SparkSingleMatrix(
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

	// Rowwise

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

	last_randomness := gpaResult.randomness[0]
	evaluation_randomness := gpaResult.randomness[1:]

	addr := CalculateAdr(api, evaluation_randomness)
	mem := calculateEQ(api, circuit.PointRow, evaluation_randomness)
	init_cntr := 0

	init_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), init_cntr), tau)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.RowFinalMerkle, matrix.RowFinalMerkleFirstRound, circuit.WHIRRow, [][]frontend.Variable{{}}, []frontend.Variable{}, rowFinalCommitment,
		[][]frontend.Variable{{matrix.RowFinalCounter}},
		[][]frontend.Variable{evaluation_randomness},
	)
	if err != nil {
		return err
	}

	final_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), matrix.RowFinalCounter), tau)

	evaluated_value := api.Add(api.Mul(init_opening, api.Sub(1, last_randomness)), api.Mul(final_opening, last_randomness))

	api.AssertIsEqual(gpaResult.lastSumcheckValue, evaluated_value)

	gpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogNumTerms+2)
	if err != nil {
		return err
	}

	claimedRS := gpaResultRSWS.claimedProducts[0]
	claimedWS := gpaResultRSWS.claimedProducts[1]

	rsws_last_randomness := gpaResultRSWS.randomness[0]
	rsws_evaluation_randomness := gpaResultRSWS.randomness[1:]

	rs_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation), tau)
	ws_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation, 1), tau)

	rsws_evaluated_value := api.Add(api.Mul(rs_opening, api.Sub(1, rsws_last_randomness)), api.Mul(ws_opening, rsws_last_randomness))

	api.AssertIsEqual(gpaResultRSWS.lastSumcheckValue, rsws_evaluated_value)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.RowwiseMerkle, matrix.RowwiseMerkleFirstRound, matrix.WHIR3, [][]frontend.Variable{{}}, []frontend.Variable{}, rowwiseCommitment,
		[][]frontend.Variable{{matrix.RowRSAddressEvaluation}, {matrix.RowRSValueEvaluation}, {matrix.RowRSTimestampEvaluation}},
		[][]frontend.Variable{rsws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(claimedInit, claimedWS), api.Mul(claimedRS, claimedFinal))

	// Colwise

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

	colwiseLast_randomness := colwiseInitFinalGpaResult.randomness[0]
	colwiseEvaluation_randomness := colwiseInitFinalGpaResult.randomness[1:]

	colwiseaddr := CalculateAdr(api, colwiseEvaluation_randomness)

	colwisemem := api.Mul(calculateEQ(api, circuit.PointCol[1:], colwiseEvaluation_randomness), api.Sub(1, circuit.PointCol[0]))
	colwiseinit_cntr := 0

	colwiseinit_opening := api.Sub(api.Add(api.Mul(colwiseaddr, colwiseGamma, colwiseGamma), api.Mul(colwisemem, colwiseGamma), colwiseinit_cntr), colwiseTau)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, circuit.SparkRLC.ColFinalMerkle, circuit.SparkRLC.ColFinalMerkleFirstRound, circuit.WHIRCol, [][]frontend.Variable{{}}, []frontend.Variable{}, colFinalCommitment,
		[][]frontend.Variable{{matrix.ColFinalCounter}},
		[][]frontend.Variable{colwiseEvaluation_randomness},
	)
	if err != nil {
		return err
	}

	colwisefinal_opening := api.Sub(api.Add(api.Mul(colwiseaddr, colwiseGamma, colwiseGamma), api.Mul(colwisemem, colwiseGamma), matrix.ColFinalCounter), colwiseTau)
	colwiseevaluated_value := api.Add(api.Mul(colwiseinit_opening, api.Sub(1, colwiseLast_randomness)), api.Mul(colwisefinal_opening, colwiseLast_randomness))
	api.AssertIsEqual(colwiseInitFinalGpaResult.lastSumcheckValue, colwiseevaluated_value)

	// Colwise RS WS

	colwisegpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogNumTerms+2)
	if err != nil {
		return err
	}

	colwiseClaimedRS := colwisegpaResultRSWS.claimedProducts[0]
	colwiseClaimedWS := colwisegpaResultRSWS.claimedProducts[1]

	colwisersws_last_randomness := colwisegpaResultRSWS.randomness[0]
	colwisersws_evaluation_randomness := colwisegpaResultRSWS.randomness[1:]

	colwisers_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation), colwiseTau)
	colwisews_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation, 1), colwiseTau)

	colwisersws_evaluated_value := api.Add(api.Mul(colwisers_opening, api.Sub(1, colwisersws_last_randomness)), api.Mul(colwisews_opening, colwisersws_last_randomness))

	api.AssertIsEqual(colwisegpaResultRSWS.lastSumcheckValue, colwisersws_evaluated_value)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, matrix.ColwiseMerkle, matrix.ColwiseMerkleFirstRound, matrix.WHIR3, [][]frontend.Variable{{}}, []frontend.Variable{}, colwiseCommitment,
		[][]frontend.Variable{{matrix.ColRSAddressEvaluation}, {matrix.ColRSValueEvaluation}, {matrix.ColRSTimestampEvaluation}},
		[][]frontend.Variable{colwisersws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(colwiseClaimedInit, colwiseClaimedWS), api.Mul(colwiseClaimedRS, colwiseClaimedFinal))

	return nil
}
