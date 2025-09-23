package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type SparseMatrix struct {
	Rows       uint64   `json:"num_rows"`
	Cols       uint64   `json:"num_cols"`
	RowIndices []uint64 `json:"new_row_indices"`
	ColIndices []uint64 `json:"col_indices"`
	Values     []uint64 `json:"values"`
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
