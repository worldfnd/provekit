package typeconv

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var bn254Modulus = func() *big.Int {
	modulus := new(big.Int)
	modulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	return modulus
}()

// BigEndian converts bytes laid out in big-endian order into a single field
// element inside the circuit.
func BigEndian(api frontend.API, values []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for i := range values {
		acc = api.Add(api.Mul(256, acc), values[i])
	}
	return acc
}

// LittleEndian converts bytes laid out in little-endian order into a single
// field element inside the circuit.
func LittleEndian(api frontend.API, values []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for i := range values {
		acc = api.Add(api.Mul(256, acc), values[len(values)-1-i])
	}
	return acc
}

// LimbsToBigIntMod converts a four-limb representation into a big.Int modulo
// the BN254 scalar field.
func LimbsToBigIntMod(limbs [4]uint64) *big.Int {
	result := new(big.Int).SetUint64(limbs[0])

	temp := new(big.Int).SetUint64(limbs[1])
	result.Add(result, temp.Lsh(temp, 64))

	temp.SetUint64(limbs[2])
	result.Add(result, temp.Lsh(temp, 128))

	temp.SetUint64(limbs[3])
	result.Add(result, temp.Lsh(temp, 192))

	result.Mod(result, bn254Modulus)
	return result
}

// LittleEndianFromUints converts a gnark uint array expressed in little-endian
// order into a single frontend variable.
func LittleEndianFromUints(api frontend.API, values []uints.U8) frontend.Variable {
	acc := frontend.Variable(0)
	for i := range values {
		acc = api.Add(api.Mul(256, acc), values[len(values)-1-i].Val)
	}
	return acc
}

// BigEndianFromUints converts a gnark uint array expressed in big-endian order
// into a single frontend variable.
func BigEndianFromUints(api frontend.API, values []uints.U8) frontend.Variable {
	acc := frontend.Variable(0)
	for i := 0; i < len(values); i++ {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, values[i].Val)
	}
	return acc
}

// LittleEndianArray converts a two-dimensional byte array laid out in
// little-endian order into circuit variables.
func LittleEndianArray(api frontend.API, values [][]frontend.Variable) []frontend.Variable {
	arr := make([]frontend.Variable, len(values))
	for j := range values {
		acc := frontend.Variable(0)
		for i := range values[j] {
			acc = api.Add(
				api.Mul(256, acc),
				values[j][len(values[j])-1-i],
			)
		}
		arr[j] = acc
	}
	return arr
}

// ByteArrayToVariables lifts a byte slice into frontend variables.
func ByteArrayToVariables(bytes []uint8) []frontend.Variable {
	arr := make([]frontend.Variable, len(bytes))
	for i := range arr {
		arr[i] = frontend.Variable(bytes[i])
	}
	return arr
}

// LittleEndianUint8ToBigInt converts a little-endian byte slice into a big.Int.
func LittleEndianUint8ToBigInt(bytes []uint8) *big.Int {
	reversed := make([]byte, len(bytes))
	for i, b := range bytes {
		reversed[len(bytes)-1-i] = b
	}

	result := new(big.Int).SetBytes(reversed)
	return result
}
