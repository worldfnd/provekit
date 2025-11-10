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
	var totalAuthPath = make([][][]frontend.Variable, len(hint.merklePaths))
	var totalLeaves = make([][][]frontend.Variable, len(hint.merklePaths))
	var totalLeafSiblingHashes = make([][]frontend.Variable, len(hint.merklePaths))
	var totalLeafIndexes = make([][]uints.U64, len(hint.merklePaths))
	var totalCapContainer = make([][]frontend.Variable, len(hint.merklePaths))

	for i, merkle_path := range hint.merklePaths {
		var numOfLeavesProved = len(merkle_path.Proofs)
		var treeHeight = len(merkle_path.Proofs[0].AuthPath)

		totalAuthPath[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeafSiblingHashes[i] = make([]frontend.Variable, numOfLeavesProved)
		totalCapContainer[i] = make([]frontend.Variable, len(merkle_path.CapContainer))

		for j := range numOfLeavesProved {
			totalAuthPath[i][j] = make([]frontend.Variable, treeHeight)
			totalLeaves[i][j] = make([]frontend.Variable, len(hint.stirAnswers[i][j]))
		}

		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)
		if !isContainer {
			for k := range merkle_path.CapContainer {
				totalCapContainer[i][k] = typeConverters.LittleEndianUint8ToBigInt(merkle_path.CapContainer[k].Digest[:])
			}
			for j := range numOfLeavesProved {
				proof := merkle_path.Proofs[j]

				for z := range treeHeight {
					totalAuthPath[i][j][z] = typeConverters.
						LittleEndianUint8ToBigInt(proof.AuthPath[z].Digest[:])
				}

				totalLeafSiblingHashes[i][j] = typeConverters.
					LittleEndianUint8ToBigInt(proof.LeafSiblingHash.Digest[:])
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
		CapContainer:      totalCapContainer,
	}
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
