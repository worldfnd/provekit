package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
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

func evaluateR1CSMatrixExtensionBatch(
	api frontend.API,
	circuit *Circuit,
	rowRand []frontend.Variable,
	colRand []frontend.Variable,
	w1Size int,
) []frontend.Variable {
	// Returns [Az1, Bz1, Cz1, Az2, Bz2, Cz2]
	rowEval := calculateEQOverBooleanHypercube(api, rowRand)
	colEval := calculateEQOverBooleanHypercube(api, colRand)

	ans := make([]frontend.Variable, 6)
	for i := range ans {
		ans[i] = frontend.Variable(0)
	}

	for i := range circuit.MatrixA {
		col := circuit.MatrixA[i].column
		row := circuit.MatrixA[i].row
		val := circuit.MatrixA[i].value

		if col < w1Size {
			ans[0] = api.Add(ans[0], api.Mul(val, api.Mul(rowEval[row], colEval[col])))
		} else {
			ans[3] = api.Add(ans[3], api.Mul(val, api.Mul(rowEval[row], colEval[col-w1Size])))
		}
	}

	for i := range circuit.MatrixB {
		col := circuit.MatrixB[i].column
		if col < w1Size {
			ans[1] = api.Add(ans[1], api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[col])))
		} else {
			ans[4] = api.Add(ans[4], api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[col-w1Size])))
		}
	}

	for i := range circuit.MatrixC {
		col := circuit.MatrixC[i].column
		if col < w1Size {
			ans[2] = api.Add(ans[2], api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[col])))
		} else {
			ans[5] = api.Add(ans[5], api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[col-w1Size])))
		}
	}

	return ans
}

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
