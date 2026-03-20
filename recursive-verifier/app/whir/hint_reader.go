package whir

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// HintReader provides on-demand access to the WHIR hint byte stream by issuing
// gnark NewHint calls. Each call advances a global byte cursor on the prover
// side, parsing raw bytes into field elements.
//
// Two hint function types are supported, matching the Rust serialization:
//   - VecHint: reads a prover_hint_ark(Vec<F>) block (8-byte length prefix + N×32 bytes)
//   - HashHint: reads a prover_hint(Hash) block (32 raw bytes, no prefix)
type HintReader struct {
	api        frontend.API
	hintInputs []frontend.Variable
	vecHint    solver.Hint
	hashHint   solver.Hint
	callIndex  int // shared global counter across Vec and Hash calls
}

// NewHintReader creates a HintReader that will issue gnark hint calls using the
// provided hint functions. The hint functions are injected from the main package
// to avoid circular imports.
func NewHintReader(api frontend.API, hintInputs []frontend.Variable, vecHint, hashHint solver.Hint) *HintReader {
	return &HintReader{
		api:        api,
		hintInputs: hintInputs,
		vecHint:    vecHint,
		hashHint:   hashHint,
	}
}

// ReadVec reads n field elements from a Vec block in the hint stream.
// Appends [callIndex, blockType=0] to inputs for unique identification.
func (h *HintReader) ReadVec(n int) []frontend.Variable {
	inputs := append(h.hintInputs, frontend.Variable(h.callIndex), frontend.Variable(0))
	h.callIndex++
	results, err := h.api.Compiler().NewHint(h.vecHint, n, inputs...)
	if err != nil {
		panic(fmt.Sprintf("ReadVec hint failed: %v", err))
	}
	return results
}

// ReadHash reads a single hash from the hint stream.
// Appends [callIndex, blockType=1] to inputs for unique identification.
func (h *HintReader) ReadHash() frontend.Variable {
	inputs := append(h.hintInputs, frontend.Variable(h.callIndex), frontend.Variable(1))
	h.callIndex++
	results, err := h.api.Compiler().NewHint(h.hashHint, 1, inputs...)
	if err != nil {
		panic(fmt.Sprintf("ReadHash hint failed: %v", err))
	}
	return results[0]
}

// Ensure hint functions match the solver.Hint signature at compile time.
var _ solver.Hint = func(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }
