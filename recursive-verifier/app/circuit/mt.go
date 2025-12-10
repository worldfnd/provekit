package circuit

import (
	"reilabs/whir-verifier-circuit/app/typeConverters"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func newMerkle(
	hint Hint,
	isContainer bool,
) Merkle {
	totalAuthPath := make([][][]frontend.Variable, len(hint.merklePaths))
	totalLeaves := make([][][]frontend.Variable, len(hint.merklePaths))
	totalLeafSiblingHashes := make([][]frontend.Variable, len(hint.merklePaths))
	totalLeafIndexes := make([][]uints.U64, len(hint.merklePaths))

	for i, merkle_path := range hint.merklePaths {
		numOfLeavesProved := len(merkle_path.Proofs)
		treeHeight := len(merkle_path.Proofs[0].AuthPath)

		totalAuthPath[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeafSiblingHashes[i] = make([]frontend.Variable, numOfLeavesProved)

		for j := range numOfLeavesProved {
			totalAuthPath[i][j] = make([]frontend.Variable, treeHeight)
			totalLeaves[i][j] = make([]frontend.Variable, len(hint.stirAnswers[i][j]))
		}

		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		if !isContainer {
			for j := range numOfLeavesProved {
				proof := merkle_path.Proofs[j]

				for z := range treeHeight {
					totalAuthPath[i][j][z] = typeConverters.
						LittleEndianUint8ToBigInt(proof.AuthPath[treeHeight-1-z].KeccakDigest[:])
				}

				totalLeafSiblingHashes[i][j] = typeConverters.
					LittleEndianUint8ToBigInt(proof.LeafSiblingHash.KeccakDigest[:])
				totalLeafIndexes[i][j] = uints.NewU64(proof.LeafIndex)

				for k := range hint.stirAnswers[i][j] {
					input := hint.stirAnswers[i][j][k]
					totalLeaves[i][j][k] = typeConverters.LimbsToBigIntMod(input.Limbs)
				}
			}
		}
	}

	return Merkle{
		Leaves:            totalLeaves,
		LeafIndexes:       totalLeafIndexes,
		LeafSiblingHashes: totalLeafSiblingHashes,
		AuthPaths:         totalAuthPath,
	}
}

func newMerkleOrEmpty(hint Hint, useHint bool, isContainer bool) Merkle {
	if !useHint {
		return Merkle{} // Empty merkle for single mode
	}
	return newMerkle(hint, isContainer)
}

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
