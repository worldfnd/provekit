package keccakSponge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Digest struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U64]
	state       [25]uints.U64
	absorb_pos  int
	squeeze_pos int
}

func NewKeccak(api frontend.API) (*Digest, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &Digest{
		api:         api,
		uapi:        uapi,
		state:       newState(),
		absorb_pos:  0,
		squeeze_pos: 136,
	}, nil
}

func NewKeccakWithTag(api frontend.API, tag []frontend.Variable) (*Digest, error) {
	d, _ := NewKeccak(api)
	for i := 136; i < 136+len(tag); i++ {
		d.state[i/8][i%8].Val = tag[i-136]
	}

	return d, nil
}

func (d *Digest) Absorb(in []frontend.Variable) {
	u8Arr := make([]uints.U8, len(in))
	for i := range in {
		u8Arr[i].Val = in[i]
	}

	for _, inputByte := range u8Arr {
		if d.absorb_pos == 136 {
			d.state = keccakf.Permute(d.uapi, d.state)
			d.absorb_pos = 0
		}
		d.state[d.absorb_pos/8][d.absorb_pos%8] = inputByte
		d.absorb_pos++
	}

	d.squeeze_pos = 136
}

func (d *Digest) AbsorbQuadraticPolynomial(in [][]frontend.Variable) {
	for i := range in {
		d.Absorb(in[i])
	}
}

func (d *Digest) Squeeze(len int) (result []frontend.Variable) {
	for i := 0; i < len; i++ {
		if d.squeeze_pos == 136 {
			d.squeeze_pos = 0
			d.absorb_pos = 0
			d.state = keccakf.Permute(d.uapi, d.state)
		}
		result = append(result, d.state[d.squeeze_pos/8][d.squeeze_pos%8].Val)
		d.squeeze_pos++
	}
	return result
}

func newState() (state [25]uints.U64) {
	for i := range state {
		state[i] = uints.NewU64(0)
	}
	return
}
