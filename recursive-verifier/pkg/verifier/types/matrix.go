package types

import "math/big"

// MatrixCell represents a single non-zero entry in a sparse matrix.
type MatrixCell struct {
	Row    int
	Column int
	Value  *big.Int
}

// SparseMatrix represents a sparse matrix in CSR format.
type SparseMatrix struct {
	Rows       uint64   `json:"num_rows"`
	Cols       uint64   `json:"num_cols"`
	RowIndices []uint64 `json:"new_row_indices"`
	ColIndices []uint64 `json:"col_indices"`
	Values     []uint64 `json:"values"`
}

// Interner stores interned field elements.
type Interner struct {
	Values []Fp256 `json:"values"`
}

// InternerAsString is a serialization helper for Interner.
type InternerAsString struct {
	Values string `json:"values"`
}

// R1CS represents a Rank-1 Constraint System.
type R1CS struct {
	PublicInputs uint64           `json:"public_inputs"`
	Witnesses    uint64           `json:"witnesses"`
	Constraints  uint64           `json:"constraints"`
	Interner     InternerAsString `json:"interner"`
	A            SparseMatrix     `json:"a"`
	B            SparseMatrix     `json:"b"`
	C            SparseMatrix     `json:"c"`
}
