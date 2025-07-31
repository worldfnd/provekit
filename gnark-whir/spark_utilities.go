package main

import (
	"github.com/consensys/gnark/frontend"
	gnark_nimue "github.com/reilabs/gnark-nimue"
)

func offline_memory_check(
	arthur gnark_nimue.Arthur,
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

	_ = tau
	_ = gamma

	return nil
}
