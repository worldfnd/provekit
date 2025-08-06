package main

import (
	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func offlineMemoryCheck(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	arthur gnark_nimue.Arthur,
	circuit *Circuit,
	randomness []frontend.Variable,
	logMemorySize int,
	logNumTerms int,
	finalCTSRowOODPoints []frontend.Variable,
	finalCTSRowOODAnswers []frontend.Variable,
	addressOODPoints []frontend.Variable,
	addressOODAnswers []frontend.Variable,
	valueOODPoints []frontend.Variable,
	valueOODAnswers []frontend.Variable,
	timeStampOODPoints []frontend.Variable,
	timeStampOODAnswers []frontend.Variable,
) error {
	tauTemp := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(tauTemp); err != nil {
		return err
	}
	tau := tauTemp[0]
	gammaTemp := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(gammaTemp); err != nil {
		return err
	}
	gamma := gammaTemp[0]

	gpa_init_claimed_val, err := gpaInitVerifier(
		api,
		arthur,
		tau,
		gamma,
		logMemorySize+1,
		randomness,
	)

	if err != nil {
		return err
	}

	gpa_final_claimed_val, err := gpaFinalVerifier(
		api,
		uapi,
		sc,
		arthur,
		circuit,
		tau,
		gamma,
		logMemorySize+1,
		randomness,
		finalCTSRowOODPoints,
		finalCTSRowOODAnswers,
	)

	if err != nil {
		return err
	}

	gpa_rs_claimed_val, err := gpaRSVerifier(
		api,
		uapi,
		sc,
		arthur,
		circuit,
		tau,
		gamma,
		logNumTerms+1,
		randomness,
		addressOODPoints,
		addressOODAnswers,
		valueOODPoints,
		valueOODAnswers,
		timeStampOODPoints,
		timeStampOODAnswers,
	)

	if err != nil {
		return err
	}

	gpa_ws_claimed_val, err := gpaWSVerifier(
		api,
		uapi,
		sc,
		arthur,
		circuit,
		tau,
		gamma,
		logNumTerms+1,
		randomness,
		addressOODPoints,
		addressOODAnswers,
		valueOODPoints,
		valueOODAnswers,
		timeStampOODPoints,
		timeStampOODAnswers,
	)

	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(gpa_init_claimed_val, gpa_ws_claimed_val), api.Mul(gpa_rs_claimed_val, gpa_final_claimed_val))

	return nil
}

func gpaInitVerifier(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	tau frontend.Variable,
	gamma frontend.Variable,
	layerCount int,
	randomness []frontend.Variable,
) (frontend.Variable, error) {
	gpaSumcheckResult, err := gpaSumcheckVerifier(
		api,
		arthur,
		layerCount,
	)
	if err != nil {
		return frontend.Variable(0), err
	}

	addr := utilities.CalculateAdr(api, gpaSumcheckResult.randomness)
	mem := calculateEQ(api, randomness, gpaSumcheckResult.randomness)
	cntr := 0

	api.AssertIsEqual(gpaSumcheckResult.lastSumcheckValue, api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), cntr), tau))

	return gpaSumcheckResult.claimedProduct, nil
}

func gpaFinalVerifier(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	arthur gnark_nimue.Arthur,
	circuit *Circuit,
	tau frontend.Variable,
	gamma frontend.Variable,
	layerCount int,
	randomness []frontend.Variable,
	finalCTSRowOODPoints []frontend.Variable,
	finalCTSRowOODAnswers []frontend.Variable,
) (frontend.Variable, error) {
	gpaSumcheckResult, err := gpaSumcheckVerifier(
		api,
		arthur,
		layerCount,
	)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedFinalCTSValue := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedFinalCTSValue); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckFinalGPAFinalCTCMerkle, circuit.WHIRParamsRow, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedFinalCTSValue[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, finalCTSRowOODPoints, finalCTSRowOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	addr := utilities.CalculateAdr(api, gpaSumcheckResult.randomness)
	mem := calculateEQ(api, randomness, gpaSumcheckResult.randomness)
	cntr := claimedFinalCTSValue[0]

	api.AssertIsEqual(gpaSumcheckResult.lastSumcheckValue, api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), cntr), tau))

	return gpaSumcheckResult.claimedProduct, nil
}

func gpaSumcheckVerifier(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	layerCount int,
) (GPASumcheckResult, error) {
	var rand []frontend.Variable
	l := make([]frontend.Variable, 2)
	r := make([]frontend.Variable, 1)
	prevRand := make([]frontend.Variable, 0)

	gpaClaimedProduct := make([]frontend.Variable, 1)
	err := arthur.FillNextScalars(gpaClaimedProduct)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	lastEval := gpaClaimedProduct[0]

	for i := 0; i < (layerCount - 1); i++ {
		rand, lastEval, err = runSumcheck(
			api,
			arthur,
			lastEval,
			i,
			4,
		)
		if err != nil {
			return GPASumcheckResult{}, err
		}

		err = arthur.FillNextScalars(l)
		if err != nil {
			return GPASumcheckResult{}, err
		}
		err = arthur.FillChallengeScalars(r)
		if err != nil {
			return GPASumcheckResult{}, err
		}
		claimedLastSch := api.Mul(
			calculateEQ(api, prevRand, rand),
			utilities.UnivarPoly(api, l, []frontend.Variable{0})[0],
			utilities.UnivarPoly(api, l, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(claimedLastSch, lastEval)
		prevRand = append(rand, r[0])
		lastEval = utilities.UnivarPoly(api, l, []frontend.Variable{r[0]})[0]
	}

	return GPASumcheckResult{
		claimedProduct:    gpaClaimedProduct[0],
		lastSumcheckValue: lastEval,
		randomness:        prevRand,
	}, nil
}

type GPASumcheckResult struct {
	claimedProduct    frontend.Variable
	lastSumcheckValue frontend.Variable
	randomness        []frontend.Variable
}

func gpaRSVerifier(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	arthur gnark_nimue.Arthur,
	circuit *Circuit,
	tau frontend.Variable,
	gamma frontend.Variable,
	layerCount int,
	randomness []frontend.Variable,
	addressOODPoints []frontend.Variable,
	addressOODAnswers []frontend.Variable,
	valueOODPoints []frontend.Variable,
	valueOODAnswers []frontend.Variable,
	timeStampOODPoints []frontend.Variable,
	timeStampOODAnswers []frontend.Variable,
) (frontend.Variable, error) {
	gpaSumcheckResult, err := gpaSumcheckVerifier(
		api,
		arthur,
		layerCount,
	)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedAddress := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedAddress); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckRSGPAAddrMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedAddress[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, addressOODPoints, addressOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedValue := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedValue); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckRSGPAValueMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedValue[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, valueOODPoints, valueOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedTimeStamp := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedTimeStamp); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckRSGPATimeStampMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedTimeStamp[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, timeStampOODPoints, timeStampOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	addr := claimedAddress[0]
	mem := claimedValue[0]
	cntr := claimedTimeStamp[0]

	api.AssertIsEqual(gpaSumcheckResult.lastSumcheckValue, api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), cntr), tau))

	return gpaSumcheckResult.claimedProduct, nil
}

func gpaWSVerifier(
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	arthur gnark_nimue.Arthur,
	circuit *Circuit,
	tau frontend.Variable,
	gamma frontend.Variable,
	layerCount int,
	randomness []frontend.Variable,
	addressOODPoints []frontend.Variable,
	addressOODAnswers []frontend.Variable,
	valueOODPoints []frontend.Variable,
	valueOODAnswers []frontend.Variable,
	timeStampOODPoints []frontend.Variable,
	timeStampOODAnswers []frontend.Variable,
) (frontend.Variable, error) {
	gpaSumcheckResult, err := gpaSumcheckVerifier(
		api,
		arthur,
		layerCount,
	)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedAddress := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedAddress); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckWSGPAAddrMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedAddress[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, addressOODPoints, addressOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedValue := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedValue); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckWSGPAValueMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedValue[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, valueOODPoints, valueOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	claimedTimeStamp := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(claimedTimeStamp); err != nil {
		return frontend.Variable(0), err
	}

	err = runWhir(api, arthur, uapi, sc, circuit.SparkAMemCheckWSGPATimeStampMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{claimedTimeStamp[0]}, [][]frontend.Variable{gpaSumcheckResult.randomness}, timeStampOODPoints, timeStampOODAnswers)
	if err != nil {
		return frontend.Variable(0), err
	}

	addr := claimedAddress[0]
	mem := claimedValue[0]
	cntr := api.Add(claimedTimeStamp[0], 1)

	api.AssertIsEqual(gpaSumcheckResult.lastSumcheckValue, api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), cntr), tau))

	return gpaSumcheckResult.claimedProduct, nil
}
