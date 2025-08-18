package typeConverters

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func BigEndian(api frontend.API, varArr []frontend.Variable) frontend.Variable {
	frontendVar := frontend.Variable(0)
	for i := range varArr {
		frontendVar = api.Add(api.Mul(256, frontendVar), varArr[i])
	}
	return frontendVar
}

func LittleEndian(api frontend.API, varArr []frontend.Variable) frontend.Variable {
	frontendVar := frontend.Variable(0)
	for i := range varArr {
		frontendVar = api.Add(api.Mul(256, frontendVar), varArr[len(varArr)-1-i])
	}
	return frontendVar
}

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

func LittleEndianFromUints(api frontend.API, varArr []uints.U8) frontend.Variable {
	frontendVar := frontend.Variable(0)
	for i := range varArr {
		frontendVar = api.Add(api.Mul(256, frontendVar), varArr[len(varArr)-1-i].Val)
	}
	return frontendVar
}

func BigEndianFromUints(api frontend.API, varArr []uints.U8) frontend.Variable {
	frontendVar := frontend.Variable(0)
	for i := 0; i < len(varArr); i++ {
		frontendVar = api.Mul(frontendVar, 256)
		frontendVar = api.Add(frontendVar, varArr[i].Val)
	}
	return frontendVar
}

func LittleEndianArr(api frontend.API, arrVarArr [][]frontend.Variable) []frontend.Variable {
	frontendArr := make([]frontend.Variable, len(arrVarArr))

	for j := range arrVarArr {
		frontendVar := frontend.Variable(0)
		for i := range arrVarArr[j] {
			frontendVar = api.Add(api.Mul(256, frontendVar), arrVarArr[j][len(arrVarArr[j])-1-i])
		}
		frontendArr[j] = frontendVar
	}
	return frontendArr
}

func ByteArrToVarArr(uint8Arr []uint8) []frontend.Variable {
	frontendArr := make([]frontend.Variable, len(uint8Arr))
	for i := range frontendArr {
		frontendArr[i] = frontend.Variable(uint8Arr[i])
	}
	return frontendArr
}
