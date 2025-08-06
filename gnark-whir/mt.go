package main

import (
	"github.com/consensys/gnark/frontend"
)

func oodAnswers(
	api frontend.API,
	answers [][]frontend.Variable,
	randomness frontend.Variable,
) (result []frontend.Variable) {

	if len(answers) == 0 {
		return nil
	}

	multiplier := frontend.Variable(1)

	first := answers[0]
	result = make([]frontend.Variable, len(first))
	for j := range first {
		result[j] = api.Mul(first[j], multiplier)
	}

	for i := 1; i < len(answers); i++ {
		multiplier = api.Mul(multiplier, randomness)

		round := answers[i]
		for j := range round {
			term := api.Mul(round[j], multiplier)
			result[j] = api.Add(result[j], term)
		}
	}

	return result
}
