package main

import (
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func calculateEQ(api frontend.API, alphas []frontend.Variable, r []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(1)
	for i, alpha := range alphas {
		ans = api.Mul(ans, api.Add(api.Mul(alpha, r[i]), api.Mul(api.Sub(frontend.Variable(1), alpha), api.Sub(frontend.Variable(1), r[i]))))
	}
	return ans
}

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnark_nimue.Arthur, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	arthur, err := gnark_nimue.NewSkyscraperArthur(api, sc, circuit.IO, circuit.Transcript[:], true)
	if err != nil {
		return nil, nil, nil, err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, arthur, uapi, nil
}

func keysFromFiles(pkPath string, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer func(pkFile *os.File) {
		err := pkFile.Close()
		if err != nil {
			log.Printf("failed to close proving key file: %v", err)
		}
	}(pkFile)

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore proving key: %w", err)

	}

	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer func(vkFile *os.File) {
		err := vkFile.Close()
		if err != nil {
			log.Printf("failed to close verifying key file: %v", err)
		}
	}(vkFile)

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore verifying key: %w", err)
	}

	return pk, vk, nil
}

func runSumcheck(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := range foldingFactor {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
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

func runZKSumcheck(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	uapi *uints.BinaryField[uints.U64],
	circuit *Circuit,
	arthur gnark_nimue.Arthur,
	lastEval frontend.Variable,
	foldingFactor int,
	polynomialDegree int,
	whirParams WHIRParams,
) ([]frontend.Variable, frontend.Variable, error) {

	rootHashes, batchingRandomness, initialOODQueries, initialOODAnswers, err := parseBatchedCommitment(api, arthur, whirParams)

	sumOfG, rhoRandomness, err := getZKSumcheckInitialValue(arthur)
	if err != nil {
		return nil, nil, err
	}

	lastEval = api.Add(lastEval, api.Mul(sumOfG, rhoRandomness))

	foldingRandomness, lastEval, err := runSumcheck(api, arthur, lastEval, foldingFactor, polynomialDegree)
	if err != nil {
		return nil, nil, err
	}

	lastEval, polynomialSums := unblindLastEval(api, arthur, lastEval, rhoRandomness)

	err = runZKWhir(api, arthur, uapi, sc, circuit.HidingSpartanMerkle, circuit.HidingSpartanFirstRound, whirParams, [][]frontend.Variable{{polynomialSums[0]}, {polynomialSums[1]}}, circuit.HidingSpartanLinearStatementEvaluations, batchingRandomness, initialOODQueries, initialOODAnswers, rootHashes)
	if err != nil {
		return nil, nil, err
	}

	return foldingRandomness, lastEval, nil
}

func getZKSumcheckInitialValue(
	arthur gnark_nimue.Arthur,
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
	arthur gnark_nimue.Arthur,
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
