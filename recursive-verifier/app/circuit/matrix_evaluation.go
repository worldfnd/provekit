package circuit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"reilabs/whir-verifier-circuit/app/typeConverters"

	"github.com/consensys/gnark/frontend"
	arkSerialize "github.com/reilabs/go-ark-serialize"
)

type SparseMatrix struct {
	Rows       uint64   `json:"num_rows"`
	Cols       uint64   `json:"num_cols"`
	RowIndices []uint64 `json:"new_row_indices"`
	ColDeltas  []uint64 `json:"col_deltas"`
	Values     []uint64 `json:"values"`
}

// DecodeColIndices converts delta-encoded column indices back to absolute indices.
// Within each row, the first column is absolute, subsequent columns are deltas from the previous.
// Returns nil if the matrix data is inconsistent (e.g., RowIndices claims more entries than ColDeltas has).
func (s *SparseMatrix) DecodeColIndices() []uint64 {
	colIndices := make([]uint64, len(s.ColDeltas))
	numRows := len(s.RowIndices)
	totalEntries := len(s.Values)

	// Validate consistency: ColDeltas and Values must have the same length
	if len(s.ColDeltas) != len(s.Values) {
		return nil
	}

	deltaIdx := 0
	for row := 0; row < numRows; row++ {
		start := int(s.RowIndices[row])
		end := totalEntries
		if row < numRows-1 {
			end = int(s.RowIndices[row+1])
		}

		rowLen := end - start
		if rowLen == 0 {
			continue
		}

		// Bounds check before accessing ColDeltas
		if deltaIdx >= len(s.ColDeltas) {
			return nil
		}

		// First column is absolute
		firstCol := s.ColDeltas[deltaIdx]
		colIndices[deltaIdx] = firstCol
		deltaIdx++

		// Subsequent columns are cumulative deltas
		prevCol := firstCol
		for i := 1; i < rowLen; i++ {
			if deltaIdx >= len(s.ColDeltas) {
				return nil
			}
			col := prevCol + s.ColDeltas[deltaIdx]
			colIndices[deltaIdx] = col
			prevCol = col
			deltaIdx++
		}
	}

	return colIndices
}

type Interner struct {
	Values []Fp256 `json:"values"`
}

type InternerAsString struct {
	Values string `json:"values"`
}

type R1CS struct {
	PublicInputs uint64           `json:"public_inputs"`
	Witnesses    uint64           `json:"witnesses"`
	Constraints  uint64           `json:"constraints"`
	Interner     InternerAsString `json:"interner"`
	A            SparseMatrix     `json:"a"`
	B            SparseMatrix     `json:"b"`
	C            SparseMatrix     `json:"c"`
}

type MatrixCell struct {
	row    int
	column int
	value  *big.Int
}

// ParseInterner decodes the hex-encoded interner from R1CS JSON into an Interner.
func ParseInterner(r1cs R1CS) (Interner, error) {
	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		return Interner{}, fmt.Errorf("decode interner hex: %w", err)
	}
	var interner Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return Interner{}, fmt.Errorf("deserialize interner: %w", err)
	}
	return interner, nil
}

// buildSparseMatrixCells converts a SparseMatrix + Interner into a flat []MatrixCell.
func buildSparseMatrixCells(sm SparseMatrix, interner Interner) ([]MatrixCell, error) {
	colIndices := sm.DecodeColIndices()
	if colIndices == nil {
		return nil, fmt.Errorf("failed to decode column indices: inconsistent data")
	}
	cells := make([]MatrixCell, len(sm.Values))
	for i := range len(sm.RowIndices) {
		end := len(sm.Values) - 1
		if i < len(sm.RowIndices)-1 {
			end = int(sm.RowIndices[i+1] - 1)
		}
		for j := int(sm.RowIndices[i]); j <= end; j++ {
			cells[j] = MatrixCell{
				row:    i,
				column: int(colIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[sm.Values[j]].Limbs),
			}
		}
	}
	return cells, nil
}

// buildR1CSMatrixCells builds MatrixCell slices for all three R1CS matrices.
func buildR1CSMatrixCells(r1cs R1CS, interner Interner) ([]MatrixCell, []MatrixCell, []MatrixCell, error) {
	a, err := buildSparseMatrixCells(r1cs.A, interner)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("matrix A: %w", err)
	}
	b, err := buildSparseMatrixCells(r1cs.B, interner)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("matrix B: %w", err)
	}
	c, err := buildSparseMatrixCells(r1cs.C, interner)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("matrix C: %w", err)
	}
	return a, b, c, nil
}

func evaluateR1CSMatrixExtension(api frontend.API, circuit *Circuit, rowRand []frontend.Variable, colRand []frontend.Variable) []frontend.Variable {
	ansA := frontend.Variable(0)
	ansB := frontend.Variable(0)
	ansC := frontend.Variable(0)

	rowEval := calculateEQOverBooleanHypercube(api, rowRand)
	colEval := calculateEQOverBooleanHypercube(api, colRand)

	for i := range len(circuit.MatrixA) {
		ansA = api.Add(ansA, api.Mul(circuit.MatrixA[i].value, api.Mul(rowEval[circuit.MatrixA[i].row], colEval[circuit.MatrixA[i].column])))
	}
	for i := range circuit.MatrixB {
		ansB = api.Add(ansB, api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[circuit.MatrixB[i].column])))
	}
	for i := range circuit.MatrixC {
		ansC = api.Add(ansC, api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[circuit.MatrixC[i].column])))
	}

	return []frontend.Variable{ansA, ansB, ansC}
}

// func evaluateR1CSMatrixExtensionBatch(
// 	api frontend.API,
// 	circuit *Circuit,
// 	rowRand []frontend.Variable,
// 	colRand []frontend.Variable,
// 	w1Size int,
// ) []frontend.Variable {
// 	// Returns [Az1, Bz1, Cz1, Az2, Bz2, Cz2]
// 	rowEval := calculateEQOverBooleanHypercube(api, rowRand)
// 	colEval := calculateEQOverBooleanHypercube(api, colRand)

// 	ans := make([]frontend.Variable, 6)
// 	for i := range ans {
// 		ans[i] = frontend.Variable(0)
// 	}

// 	for i := range circuit.MatrixA {
// 		col := circuit.MatrixA[i].column
// 		row := circuit.MatrixA[i].row
// 		val := circuit.MatrixA[i].value

// 		if col < w1Size {
// 			ans[0] = api.Add(ans[0], api.Mul(val, api.Mul(rowEval[row], colEval[col])))
// 		} else {
// 			ans[3] = api.Add(ans[3], api.Mul(val, api.Mul(rowEval[row], colEval[col-w1Size])))
// 		}
// 	}

// 	for i := range circuit.MatrixB {
// 		col := circuit.MatrixB[i].column
// 		if col < w1Size {
// 			ans[1] = api.Add(ans[1], api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[col])))
// 		} else {
// 			ans[4] = api.Add(ans[4], api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[col-w1Size])))
// 		}
// 	}

// 	for i := range circuit.MatrixC {
// 		col := circuit.MatrixC[i].column
// 		if col < w1Size {
// 			ans[2] = api.Add(ans[2], api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[col])))
// 		} else {
// 			ans[5] = api.Add(ans[5], api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[col-w1Size])))
// 		}
// 	}

// 	return ans
// }

func calculateEQOverBooleanHypercube(api frontend.API, r []frontend.Variable) []frontend.Variable {
	ans := []frontend.Variable{frontend.Variable(1)}

	for i := len(r) - 1; i >= 0; i-- {
		x := r[i]
		left := make([]frontend.Variable, len(ans))
		right := make([]frontend.Variable, len(ans))

		for j, y := range ans {
			left[j] = api.Mul(y, api.Sub(1, x))
			right[j] = api.Mul(y, x)
		}

		ans = append(left, right...)
	}

	return ans
}

// blindingCovectorMLE computes the MLE evaluation of the blinding OffsetCovector
// at the given evaluation point. This mirrors Rust's OffsetCovector::mle_evaluate
// for the blinding polynomial weights expand_powers::<4>(alpha) at offset w1Size.
//
// weights[4*j + k] = alpha[j]^k for k in 0..4, placed at domain index w1Size + 4*j + k.
func blindingCovectorMLE(api frontend.API, alpha []frontend.Variable, w1Size int, evaluationPoint []frontend.Variable) frontend.Variable {
	n := len(evaluationPoint)
	result := frontend.Variable(0)

	api.Println("=== blindingCovectorMLE debug ===")
	api.Println("blindingCovectorMLE: n(eval_point_len)", n, "w1Size", w1Size, "alpha_len", len(alpha))
	for j, a := range alpha {
		api.Println("blindingCovectorMLE: alpha", j, a)
	}

	// expand_powers::<4>(alpha) produces [1, α₀, α₀², α₀³, 1, α₁, α₁², α₁³, ...]
	for j := range alpha {
		alphaPow := frontend.Variable(1) // alpha[j]^0
		for k := 0; k < 4; k++ {
			idx := w1Size + 4*j + k

			// Compute Lagrange basis: Π_bit point[bit] or (1-point[bit])
			basis := frontend.Variable(1)
			for b := 0; b < n; b++ {
				if (idx>>(n-1-b))&1 == 1 {
					basis = api.Mul(basis, evaluationPoint[b])
				} else {
					basis = api.Mul(basis, api.Sub(1, evaluationPoint[b]))
				}
			}

			api.Println("blindingCovectorMLE: j", j, "k", k, "idx", idx, "weight", alphaPow, "basis", basis)
			result = api.Add(result, api.Mul(alphaPow, basis))
			alphaPow = api.Mul(alphaPow, alpha[j])
		}
	}
	api.Println("blindingCovectorMLE: result", result)
	return result
}

// geometricTill evaluates the multilinear extension of the geometric vector
// [1, x, x^2, ..., x^{n-1}, 0, ..., 0] at point foldingRandomness.
// This is O(k) constraints where k = len(foldingRandomness).
// Used for the public weight MLE evaluation (make_public_weight in Rust).
func geometricTill(api frontend.API, x frontend.Variable, n int, foldingRandomness []frontend.Variable) frontend.Variable {
	k := len(foldingRandomness)
	if n <= 0 || n > (1<<k) {
		panic(fmt.Sprintf("geometricTill: invalid n=%d for k=%d", n, k))
	}

	borrow0 := frontend.Variable(1)
	borrow1 := frontend.Variable(0)

	for i := range k {
		ri := foldingRandomness[k-1-i]
		bn := ((n - 1) >> i) & 1 // i-th bit of n-1

		b0 := api.Sub(1, ri)
		b1 := api.Mul(x, ri)

		if bn == 0 {
			newBorrow0 := api.Mul(b0, borrow0)
			newBorrow1 := api.Add(api.Mul(api.Add(b0, b1), borrow1), api.Mul(b1, borrow0))
			borrow0 = newBorrow0
			borrow1 = newBorrow1
		} else {
			newBorrow0 := api.Add(api.Mul(api.Add(b0, b1), borrow0), api.Mul(b0, borrow1))
			newBorrow1 := api.Mul(b1, borrow1)
			borrow0 = newBorrow0
			borrow1 = newBorrow1
		}

		x = api.Mul(x, x)
	}

	return borrow0
}
