package circuit

import (
	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
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

// rlcBatchedLeaves collapses a wide leaf (length foldSize * batchSize) into foldSize via
// out[j] = sum_{b=0..batchSize-1} B^b * leaf[b*foldSize + j]
func rlcBatchedLeaves(api frontend.API, leaves [][]frontend.Variable, foldSize int, batchSize int, B frontend.Variable) [][]frontend.Variable {
	// Precompute powers of B: [1, B, B^2, ..., B^(batchSize-1)]
	powers := make([]frontend.Variable, batchSize)
	powers[0] = frontend.Variable(1)
	for b := 1; b < batchSize; b++ {
		powers[b] = api.Mul(powers[b-1], B)
	}

	collapsed := make([][]frontend.Variable, len(leaves))
	for i := range leaves {
		collapsed[i] = make([]frontend.Variable, foldSize)
		for j := 0; j < foldSize; j++ {
			sum := frontend.Variable(0)
			for b := 0; b < batchSize; b++ {
				idx := b*foldSize + j
				sum = api.Add(sum, api.Mul(powers[b], leaves[i][idx]))
			}
			collapsed[i][j] = sum
		}
	}
	return collapsed
}

// hashPublicInputs computes the hash of public inputs as field elements sequentially
func hashPublicInputs(sc *skyscraper.Skyscraper, publicInputs PublicInputs) (frontend.Variable, error) {

	if len(publicInputs.Values) == 0 {
		return frontend.Variable(0), nil
	}

	// For single element, we hash it with a zero
	if len(publicInputs.Values) == 1 {
		return sc.CompressV2(publicInputs.Values[0], frontend.Variable(0)), nil
	}

	// For 2+ elements, use standard approach
	hash := sc.CompressV2(publicInputs.Values[0], publicInputs.Values[1])
	for i := 2; i < len(publicInputs.Values); i++ {
		hash = sc.CompressV2(hash, publicInputs.Values[i])
	}

	return hash, nil
}
