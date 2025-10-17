package types

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// MerklePaths stores Merkle proof inputs parsed from transcripts.
type MerklePaths struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][][]uints.U8
	AuthPaths         [][][][]uints.U8
}

// Merkle captures Merkle witnesses expressed as circuit variables.
type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][]frontend.Variable
	AuthPaths         [][][]frontend.Variable
}

// Commitment represents a Merkle commitment and associated random challenges.
type Commitment struct {
	RootHash           frontend.Variable
	BatchingRandomness frontend.Variable
	InitialOODQueries  []frontend.Variable
	InitialOODAnswers  [][]frontend.Variable
}
