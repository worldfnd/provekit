package whir

import (
	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// geometricChallenge mirrors Rust's geometric_challenge.
// Returns [1] for count <= 1 (no entropy sourced), or [1, x, x^2, ..., x^{count-1}]
// for count > 1 where x is squeezed from the transcript.
func geometricChallenge(api frontend.API, nimue gnarkNimue.Nimue, count int) ([]frontend.Variable, error) {
	switch count {
	case 0:
		return nil, nil
	case 1:
		return []frontend.Variable{frontend.Variable(1)}, nil
	default:
		x := make([]frontend.Variable, 1)
		if err := nimue.FillChallengeScalars(x); err != nil {
			return nil, err
		}
		return ExpandRandomness(api, x[0], count), nil
	}
}

// Given some randomness r, return a vector r^0, r^1,...r^{len-1}
func ExpandRandomness(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := frontend.Variable(1)
	for i := range len {
		res[i] = acc
		acc = api.Mul(acc, base)
	}
	return res
}

func DotProduct(api frontend.API, a []frontend.Variable, b []frontend.Variable) frontend.Variable {
	var acc = frontend.Variable(0)
	for i := range a {
		acc = api.Add(acc, api.Mul(a[i], b[i]))
	}
	return acc
}

// TensorProduct computes the tensor (Kronecker) product of two vectors:
// result[i*len(b) + j] = a[i] * b[j]
func TensorProduct(api frontend.API, a []frontend.Variable, b []frontend.Variable) []frontend.Variable {
	result := make([]frontend.Variable, len(a)*len(b))
	for i, x := range a {
		for j, y := range b {
			result[i*len(b)+j] = api.Mul(x, y)
		}
	}
	return result
}

func MultivarPoly(coefs []frontend.Variable, vars []frontend.Variable, api frontend.API) frontend.Variable {
	if len(vars) == 0 {
		return coefs[0]
	}
	deg_zero := MultivarPoly(coefs[:len(coefs)/2], vars[:len(vars)-1], api)
	deg_one := api.Mul(vars[len(vars)-1], MultivarPoly(coefs[len(coefs)/2:], vars[:len(vars)-1], api))
	return api.Add(deg_zero, deg_one)
}

func UnivarPoly(api frontend.API, coefficients []frontend.Variable, points []frontend.Variable) []frontend.Variable {
	if len(points) == 0 {
		return coefficients
	}

	results := make([]frontend.Variable, len(points))
	for j := range points {
		ans := frontend.Variable(0)
		for i := range coefficients {
			ans = api.Add(api.Mul(ans, points[j]), coefficients[len(coefficients)-1-i])
		}
		results[j] = ans
	}
	return results
}

// computeEqWeights computes eq(point, p) for all binary points p on the hypercube.
// Mirrors Rust MultilinearPoint::eq_weights / eq_poly.
// For point = [r_0, ..., r_{n-1}], returns 2^n values where
// result[p] = ∏_i (bit_i(p) ? r_{n-1-i} : (1 - r_{n-1-i}))
// matching Rust's reverse-iteration convention in eq_poly.
func computeEqWeights(api frontend.API, point []frontend.Variable) []frontend.Variable {
	n := len(point)
	size := 1 << n
	result := make([]frontend.Variable, size)
	result[0] = frontend.Variable(1)
	cur := 1
	for i := 0; i < n; i++ {
		for j := cur - 1; j >= 0; j-- {
			lo := api.Mul(result[j], api.Sub(frontend.Variable(1), point[i]))
			hi := api.Sub(result[j], lo) // result[j]*point[i] = result[j] - lo
			result[2*j] = lo
			result[2*j+1] = hi
		}
		cur *= 2
	}
	return result
}

// UnivarMleEvaluate computes the multilinear extension of the univariate
// evaluation linear form (1, x, x^2, ..., x^{2^n - 1}) at a given point.
// Mirrors Rust UnivariateEvaluation::mle_evaluate:
//
//	Π_i ((1 - r_i) + r_i · x^{2^{n-1-i}})
//
// This is NOT the same as EqPolyOutside(ExpandFromUnivariate(x, n), r)
// which computes the eq polynomial between expanded coordinates and r.
func UnivarMleEvaluate(api frontend.API, univarPoint frontend.Variable, point []frontend.Variable) frontend.Variable {
	n := len(point)
	result := frontend.Variable(1)
	x2i := univarPoint
	for i := n - 1; i >= 0; i-- {
		factor := api.Add(api.Sub(frontend.Variable(1), point[i]), api.Mul(point[i], x2i))
		result = api.Mul(result, factor)
		x2i = api.Mul(x2i, x2i)
	}
	return result
}

// MultilinearEvalCircuit evaluates the multilinear extension of `values` at
// `point`: MLE(point) = Σ_i values[i] * eq(i, point).
// len(values) must equal 2^len(point).
func MultilinearEvalCircuit(api frontend.API, point []frontend.Variable, values []frontend.Variable) frontend.Variable {
	eqW := computeEqWeights(api, point)
	return DotProduct(api, eqW, values)
}

// verifyMerkleProofs verifies Merkle membership proofs using Skyscraper CompressV2.
// Each leaf is hashed to a single field element, then the auth path is traversed
// up to the root.
func verifyMerkleProofs(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	leaves [][]frontend.Variable,
	leafIndexes []frontend.Variable,
	siblingHashes []frontend.Variable,
	authPaths [][]frontend.Variable,
	rootHash frontend.Variable,
) {
	for i := range leaves {
		treeHeight := len(authPaths[i]) + 1
		leafIndexBits := api.ToBinary(leafIndexes[i], treeHeight)

		// Hash the leaf elements into a single commitment.
		claimedLeafHash := sc.CompressV2(leaves[i][0], leaves[i][1])
		for x := 2; x < len(leaves[i]); x++ {
			claimedLeafHash = sc.CompressV2(claimedLeafHash, leaves[i][x])
		}

		// Level 0: combine with sibling.
		dir := leafIndexBits[0]
		left := api.Select(dir, siblingHashes[i], claimedLeafHash)
		right := api.Select(dir, claimedLeafHash, siblingHashes[i])
		currentHash := sc.CompressV2(left, right)

		// Remaining levels.
		for level := 1; level < treeHeight; level++ {
			indexBit := api.And(leafIndexBits[level], 1)
			left = api.Select(indexBit, authPaths[i][level-1], currentHash)
			right = api.Select(indexBit, currentHash, authPaths[i][level-1])
			currentHash = sc.CompressV2(left, right)
		}
		api.AssertIsEqual(currentHash, rootHash)
	}
}
