package matrix

import (
	"github.com/consensys/gnark/frontend"

	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

// EvaluateR1CSMatrixExtension evaluates the R1CS matrices over the provided
// multilinear extension points.
func EvaluateR1CSMatrixExtension(
	api frontend.API,
	matrixA []types.MatrixCell,
	matrixB []types.MatrixCell,
	matrixC []types.MatrixCell,
	rowRand []frontend.Variable,
	colRand []frontend.Variable,
) []frontend.Variable {
	ansA := frontend.Variable(0)
	ansB := frontend.Variable(0)
	ansC := frontend.Variable(0)

	rowEval := calculateEQOverBooleanHypercube(api, rowRand)
	colEval := calculateEQOverBooleanHypercube(api, colRand)

	for i := range matrixA {
		ansA = api.Add(
			ansA,
			api.Mul(
				matrixA[i].Value,
				rowEval[matrixA[i].Row],
				colEval[matrixA[i].Column],
			),
		)
	}
	for i := range matrixB {
		ansB = api.Add(
			ansB,
			api.Mul(
				matrixB[i].Value,
				rowEval[matrixB[i].Row],
				colEval[matrixB[i].Column],
			),
		)
	}
	for i := range matrixC {
		ansC = api.Add(
			ansC,
			api.Mul(
				matrixC[i].Value,
				rowEval[matrixC[i].Row],
				colEval[matrixC[i].Column],
			),
		)
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
