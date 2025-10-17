package keccak

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

// Digest implements a keccak sponge compatible with gnark circuits.
type Digest struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U64]
	state      [25]uints.U64
	absorbPos  int
	squeezePos int
}

// New creates a fresh keccak sponge bound to the provided API.
func New(api frontend.API) (*Digest, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &Digest{
		api:        api,
		uapi:       uapi,
		state:      newState(),
		absorbPos:  0,
		squeezePos: 136,
	}, nil
}

// NewWithTag initialises a new sponge with the supplied tag already absorbed.
func NewWithTag(api frontend.API, tag []frontend.Variable) (*Digest, error) {
	d, err := New(api)
	if err != nil {
		return nil, err
	}
	for i := 136; i < 136+len(tag); i++ {
		d.state[i/8][i%8].Val = tag[i-136]
	}
	return d, nil
}

// Absorb consumes the provided bytes into the sponge state.
func (d *Digest) Absorb(inputs []frontend.Variable) {
	u8Arr := make([]uints.U8, len(inputs))
	for i := range inputs {
		u8Arr[i].Val = inputs[i]
	}

	for _, inputByte := range u8Arr {
		if d.absorbPos == 136 {
			d.state = keccakf.Permute(d.uapi, d.state)
			d.absorbPos = 0
		}
		d.state[d.absorbPos/8][d.absorbPos%8] = inputByte
		d.absorbPos++
	}

	d.squeezePos = 136
}

// AbsorbQuadraticPolynomial absorbs a quadratic polynomial expressed as a
// two-dimensional slice of variables.
func (d *Digest) AbsorbQuadraticPolynomial(values [][]frontend.Variable) {
	for i := range values {
		d.Absorb(values[i])
	}
}

// Squeeze emits the requested number of bytes from the sponge.
func (d *Digest) Squeeze(length int) []frontend.Variable {
	var result []frontend.Variable
	for i := 0; i < length; i++ {
		if d.squeezePos == 136 {
			d.squeezePos = 0
			d.absorbPos = 0
			d.state = keccakf.Permute(d.uapi, d.state)
		}
		result = append(result, d.state[d.squeezePos/8][d.squeezePos%8].Val)
		d.squeezePos++
	}
	return result
}

func newState() [25]uints.U64 {
	var state [25]uints.U64
	for i := range state {
		state[i] = uints.NewU64(0)
	}
	return state
}
