package circuit

import (
	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
)

func zkWHIRCommitmentParsing(api frontend.API, nimue gnarkNimue.Nimue, blindedCommitmentWhirConfig WHIRParams, blindingCommitmentWhirConfig WHIRParams, numPolynomials int) ([]Commitment, Commitment, error) {
	fHat := make([]Commitment, numPolynomials)
	for i := 0; i < numPolynomials; i++ {
		blindedCommitment, err := irsReceiveCommitment(api, nimue, blindedCommitmentWhirConfig)
		if err != nil {
			api.Println("parse commitment 1")
			return []Commitment{}, Commitment{}, err
		}
		fHat[i] = blindedCommitment
		api.Println("blindedCommitment", blindedCommitment)
	}

	blindingCommitment, err := irsReceiveCommitment(api, nimue, blindingCommitmentWhirConfig)
	api.Println("blindingCommitment", blindingCommitment)
	if err != nil {
		return []Commitment{}, Commitment{}, err
	}

	return fHat, blindingCommitment, nil
}

func irsReceiveCommitment(api frontend.API, nimue gnarkNimue.Nimue, whir_params WHIRParams) (Commitment, error) {
	rootHash := make([]frontend.Variable, 1)
	if err := nimue.FillNextScalars(rootHash); err != nil {
		return Commitment{}, err
	}

	// OOD samples count comes from the commitment's out_domain_samples config.
	oodSamples := whir_params.CommittmentOODSamples
	oodPoints := make([]frontend.Variable, oodSamples)

	if err := nimue.FillChallengeScalars(oodPoints); err != nil {
		return Commitment{}, err
	}

	// Total OOD answers = ood_samples * batch_size (mirrors Rust irs_commit receive_commitment).
	totalOODAnswers := oodSamples * whir_params.BatchSize
	oodAnswers := make([][]frontend.Variable, totalOODAnswers)
	for i := range totalOODAnswers {
		oodAnswer := make([]frontend.Variable, 1)

		if err := nimue.FillNextScalars(oodAnswer); err != nil {
			return Commitment{}, err
		}
		oodAnswers[i] = oodAnswer
	}
	return Commitment{
		RootHash:          rootHash[0],
		InitialOODQueries: oodPoints,
		InitialOODAnswers: oodAnswers,
	}, nil
}
