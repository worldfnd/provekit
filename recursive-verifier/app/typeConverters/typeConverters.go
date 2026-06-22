package typeConverters

import (
	"math/big"
)

func LimbsToBigIntMod(limbs [4]uint64) *big.Int {
	modulus := new(big.Int)
	modulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	result := new(big.Int).SetUint64(limbs[0])

	temp := new(big.Int).SetUint64(limbs[1])
	result.Add(result, temp.Lsh(temp, 64))

	temp.SetUint64(limbs[2])
	result.Add(result, temp.Lsh(temp, 128))

	temp.SetUint64(limbs[3])
	result.Add(result, temp.Lsh(temp, 192))

	result.Mod(result, modulus)

	return result
}
