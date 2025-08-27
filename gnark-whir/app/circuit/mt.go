package circuit

import (
	"reilabs/whir-verifier-circuit/app/typeConverters"
	"reilabs/whir-verifier-circuit/app/utilities"

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

	for i, merkle_path := range hint.merklePaths {
		var numOfLeavesProved = len(merkle_path.LeafIndexes)
		var treeHeight = len(merkle_path.AuthPathsSuffixes[0])

		totalAuthPath[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeafSiblingHashes[i] = make([]frontend.Variable, numOfLeavesProved)

		for j := range numOfLeavesProved {
			totalAuthPath[i][j] = make([]frontend.Variable, treeHeight)
			totalLeaves[i][j] = make([]frontend.Variable, len(hint.stirAnswers[i][j]))
		}

		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		if !isContainer {
			var authPathsTemp = make([][]KeccakDigest, numOfLeavesProved)
			var prevPath = merkle_path.AuthPathsSuffixes[0]
			authPathsTemp[0] = utilities.Reverse(prevPath)

			for j := range totalAuthPath[i][0] {
				totalAuthPath[i][0][j] = typeConverters.LittleEndianUint8ToBigInt(authPathsTemp[0][j].KeccakDigest[:])
			}

			for j := 1; j < numOfLeavesProved; j++ {
				prevPath = utilities.PrefixDecodePath(prevPath, merkle_path.AuthPathsPrefixLengths[j], merkle_path.AuthPathsSuffixes[j])
				authPathsTemp[j] = utilities.Reverse(prevPath)
				for z := 0; z < treeHeight; z++ {
					totalAuthPath[i][j][z] = typeConverters.LittleEndianUint8ToBigInt(authPathsTemp[j][z].KeccakDigest[:])
				}
			}

			for z := range numOfLeavesProved {
				totalLeafSiblingHashes[i][z] = typeConverters.LittleEndianUint8ToBigInt(merkle_path.LeafSiblingHashes[z].KeccakDigest[:])
				totalLeafIndexes[i][z] = uints.NewU64(merkle_path.LeafIndexes[z])
				for j := range hint.stirAnswers[i][z] {
					input := hint.stirAnswers[i][z][j]
					totalLeaves[i][z][j] = typeConverters.LimbsToBigIntMod(input.Limbs)
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
