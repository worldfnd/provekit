package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"

	"reilabs/whir-verifier-circuit/pkg/crypto/polynomial"
	"reilabs/whir-verifier-circuit/pkg/verifier/merkle"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
	"reilabs/whir-verifier-circuit/pkg/verifier/whir"
)

func gpaSumcheckVerifier(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	layerCount int,
) (GPASumcheckResult, error) {
	l := make([]frontend.Variable, 2)
	r := make([]frontend.Variable, 1)

	gpaClaimedValues := make([]frontend.Variable, 2)
	err := arthur.FillNextScalars(gpaClaimedValues)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	err = arthur.FillChallengeScalars(r)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	lastEval := polynomial.Univar(api, gpaClaimedValues, []frontend.Variable{r[0]})[0]
	prevRand := []frontend.Variable{r[0]}
	var rand []frontend.Variable

	for i := 1; i < (layerCount - 1); i++ {
		rand, lastEval, err = RunSumcheck(
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
			polynomial.Univar(api, l, []frontend.Variable{0})[0],
			polynomial.Univar(api, l, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(claimedLastSch, lastEval)
		prevRand = append(rand, r[0])
		lastEval = polynomial.Univar(api, l, []frontend.Variable{r[0]})[0]
	}

	return GPASumcheckResult{
		claimedProducts:   gpaClaimedValues,
		lastSumcheckValue: lastEval,
		randomness:        prevRand,
	}, nil
}

type GPASumcheckResult struct {
	claimedProducts   []frontend.Variable
	lastSumcheckValue frontend.Variable
	randomness        []frontend.Variable
}

func CalculateAdr(api frontend.API, coefficients []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(0)
	for _, coefficient := range coefficients {
		ans = api.Add(api.Mul(ans, 2), coefficient)
	}

	return ans
}

func RunSumcheck(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := 0; i < foldingFactor; i++ {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
			return nil, nil, err
		}
		foldingRandomness[i] = foldingRandomnessTemp[0]
		sumcheckVal := api.Add(
			polynomial.Univar(api, sumcheckPolynomial, []frontend.Variable{0})[0],
			polynomial.Univar(api, sumcheckPolynomial, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(sumcheckVal, lastEval)
		lastEval = polynomial.Univar(api, sumcheckPolynomial, []frontend.Variable{foldingRandomness[i]})[0]
	}
	return foldingRandomness, lastEval, nil
}

func RunZKSumcheck(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	uapi *uints.BinaryField[uints.U64],
	circuit *Circuit,
	arthur gnarkNimue.Arthur,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
	whirParams types.WHIRParams,
) ([]frontend.Variable, frontend.Variable, error) {
	commitment, err := merkle.ParseCommitment(arthur, whirParams)
	if err != nil {
		return nil, nil, err
	}

	sumOfG, rhoRandomness, err := getZKSumcheckInitialValue(arthur)
	if err != nil {
		return nil, nil, err
	}

	lastEval = api.Add(lastEval, api.Mul(sumOfG, rhoRandomness))

	foldingRandomness, lastEval, err := RunSumcheck(api, arthur, lastEval, foldingFactor, polynomialDegree)
	if err != nil {
		return nil, nil, err
	}

	lastEval, polynomialSums := unblindLastEval(api, arthur, lastEval, rhoRandomness)

	_, err = whir.RunZKWhir(api, arthur, uapi, sc, circuit.HidingSpartanMerkle, circuit.HidingSpartanFirstRound, whirParams, [][]frontend.Variable{{polynomialSums[0]}, {polynomialSums[1]}}, circuit.HidingSpartanLinearStatementEvaluations, commitment,
		[][]frontend.Variable{{}, {}},
		[][]frontend.Variable{},
	)
	if err != nil {
		return nil, nil, err
	}

	return foldingRandomness, lastEval, nil
}

func getZKSumcheckInitialValue(
	arthur gnarkNimue.Arthur,
) (frontend.Variable, frontend.Variable, error) {
	sumOfG := make([]frontend.Variable, 1)
	rhoRandomness := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(sumOfG); err != nil {
		return nil, nil, err
	}
	if err := arthur.FillChallengeScalars(rhoRandomness); err != nil {
		return nil, nil, err
	}
	return sumOfG[0], rhoRandomness[0], nil
}

func unblindLastEval(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	lastEval frontend.Variable,
	rhoRandomness frontend.Variable,
) (frontend.Variable, []frontend.Variable) {
	polynomialSums := make([]frontend.Variable, 2)
	if err := arthur.FillNextScalars(polynomialSums); err != nil {
		return 0, nil
	}

	lastEval = api.Sub(lastEval, api.Mul(polynomialSums[0], rhoRandomness))
	return lastEval, polynomialSums
}
