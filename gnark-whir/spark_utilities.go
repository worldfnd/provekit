package main

import (
	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark/frontend"
	gnark_nimue "github.com/reilabs/gnark-nimue"
)

func offlineMemoryCheck(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	randomness []frontend.Variable,
	logMemorySize int,
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

	gpaInitVerifier(
		api,
		arthur,
		tau,
		gamma,
		logMemorySize+1,
		randomness,
	)

	return nil
}

func gpaInitVerifier(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	tau frontend.Variable,
	gamma frontend.Variable,
	layerCount int,
	randomness []frontend.Variable,
) error {
	_, err := gpaSumcheckVerifier(
		api,
		arthur,
		layerCount,
	)
	if err != nil {
		return err
	}

	_ = tau
	_ = gamma
	_ = randomness

	return nil
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
	err := arthur.FillChallengeScalars(gpaClaimedProduct)
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

		err = arthur.FillChallengeScalars(l)
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
