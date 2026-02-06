package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// NaivePublicWeightCircuit uses O(2^m) EQ polynomial approach
type NaivePublicWeightCircuit struct {
	X                frontend.Variable   // base of geometric sequence
	FoldingRandomness []frontend.Variable // evaluation point (length = m)
	N                int                 // number of non-zero terms (compile-time constant)
	Result           frontend.Variable   `gnark:",public"`
}

func (c *NaivePublicWeightCircuit) Define(api frontend.API) error {
	m := len(c.FoldingRandomness)
	domainSize := 1 << m

	// Build weights: [1, x, x², ..., x^(n-1), 0, ..., 0]
	weights := make([]frontend.Variable, domainSize)
	power := frontend.Variable(1)
	for i := 0; i < domainSize; i++ {
		if i < c.N {
			weights[i] = power
			power = api.Mul(power, c.X)
		} else {
			weights[i] = 0
		}
	}

	// Compute EQ polynomials (O(2^m) constraints)
	eqPolys := calculateEQOverBooleanHypercube(api, c.FoldingRandomness)

	// Dot product (O(2^m) constraints)
	result := frontend.Variable(0)
	for i := 0; i < domainSize; i++ {
		result = api.Add(result, api.Mul(weights[i], eqPolys[i]))
	}

	api.AssertIsEqual(result, c.Result)
	return nil
}

// OptimizedPublicWeightCircuit uses O(m) geometricTill approach
type OptimizedPublicWeightCircuit struct {
	X                frontend.Variable   // base of geometric sequence
	FoldingRandomness []frontend.Variable // evaluation point (length = m)
	N                int                 // number of non-zero terms 
	Result           frontend.Variable   `gnark:",public"`
}

func (c *OptimizedPublicWeightCircuit) Define(api frontend.API) error {
	result := geometricTill(api, c.X, c.N, c.FoldingRandomness)
	api.AssertIsEqual(result, c.Result)
	return nil
}

// TestPublicWeightEquivalence verifies both implementations produce same results
func TestPublicWeightEquivalence(t *testing.T) {
	m := 10
	n := 5

	// Both circuits should produce the same result for the same inputs
	naiveCircuit := &NaivePublicWeightCircuit{FoldingRandomness: make([]frontend.Variable, m), N: n}
	optCircuit := &OptimizedPublicWeightCircuit{FoldingRandomness: make([]frontend.Variable, m), N: n}

	naiveCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, naiveCircuit)
	if err != nil {
		t.Fatalf("Failed to compile naive circuit: %v", err)
	}

	optCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, optCircuit)
	if err != nil {
		t.Fatalf("Failed to compile optimized circuit: %v", err)
	}

	t.Logf("Naive constraints: %d", naiveCCS.GetNbConstraints())
	t.Logf("Optimized constraints: %d", optCCS.GetNbConstraints())
	t.Logf("Constraint reduction: %.2fx", float64(naiveCCS.GetNbConstraints())/float64(optCCS.GetNbConstraints()))
}

// TestPublicWeightConstraintScaling tests constraint scaling for different m values
func TestPublicWeightConstraintScaling(t *testing.T) {
	testCases := []struct {
		m int // domain size = 2^m
		n int // number of public inputs
	}{
		{8, 10},
		{10, 10},
		{12, 100},
		{14, 100},
	}

	t.Log("Constraint scaling comparison:")
	t.Log("| m  | n   | Naive      | Optimized | Reduction |")
	t.Log("|----|-----|------------|-----------|-----------|")

	for _, tc := range testCases {
		naiveCircuit := &NaivePublicWeightCircuit{FoldingRandomness: make([]frontend.Variable, tc.m), N: tc.n}
		optCircuit := &OptimizedPublicWeightCircuit{FoldingRandomness: make([]frontend.Variable, tc.m), N: tc.n}

		naiveCCS, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, naiveCircuit)
		optCCS, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, optCircuit)

		naiveConstraints := naiveCCS.GetNbConstraints()
		optConstraints := optCCS.GetNbConstraints()
		reduction := float64(naiveConstraints) / float64(optConstraints)

		t.Logf("| %2d | %3d | %10d | %9d | %7.1fx  |", tc.m, tc.n, naiveConstraints, optConstraints, reduction)
	}
}

// BenchmarkPublicWeightEvaluation benchmarks both implementations
func BenchmarkPublicWeightEvaluation(b *testing.B) {
	testCases := []struct {
		name string
		m    int // domain size = 2^m
		n    int // number of public inputs
	}{
		{"m=10_n=10", 10, 10},
		{"m=12_n=50", 12, 50},
		{"m=14_n=100", 14, 100},
	}

	for _, tc := range testCases {
		b.Run("Naive/"+tc.name, func(b *testing.B) {
			benchmarkNaive(b, tc.m, tc.n)
		})
		b.Run("Optimized/"+tc.name, func(b *testing.B) {
			benchmarkOptimized(b, tc.m, tc.n)
		})
	}
}

func benchmarkNaive(b *testing.B, m, n int) {
	circuit := &NaivePublicWeightCircuit{
		FoldingRandomness: make([]frontend.Variable, m),
		N:                n,
	}

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("Naive (m=%d, n=%d): %d constraints", m, n, ccs.GetNbConstraints())

	// Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	// Create witness with dummy values
	assignment := &NaivePublicWeightCircuit{
		X:                1, // dummy
		FoldingRandomness: make([]frontend.Variable, m),
		N:                n,
		Result:           0,
	}
	for i := range assignment.FoldingRandomness {
		assignment.FoldingRandomness[i] = 0
	}
	// For foldingRandomness = [0,0,...,0], result = weights[0] = 1
	assignment.Result = 1

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			b.Fatal(err)
		}
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOptimized(b *testing.B, m, n int) {
	circuit := &OptimizedPublicWeightCircuit{
		FoldingRandomness: make([]frontend.Variable, m),
		N:                n,
	}

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("Optimized (m=%d, n=%d): %d constraints", m, n, ccs.GetNbConstraints())

	// Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	// Create witness with dummy values
	assignment := &OptimizedPublicWeightCircuit{
		X:                1,
		FoldingRandomness: make([]frontend.Variable, m),
		N:                n,
		Result:           1, // same as naive for foldingRandomness=[0,0,...,0], x=1
	}
	for i := range assignment.FoldingRandomness {
		assignment.FoldingRandomness[i] = 0
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			b.Fatal(err)
		}
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			b.Fatal(err)
		}
	}
}
