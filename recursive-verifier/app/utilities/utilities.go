package utilities

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

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

func IndexOf(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output")
	}

	if len(inputs) == 0 {
		return fmt.Errorf("inputs array cannot be empty")
	}

	target := inputs[0]

	for i := 1; i < len(inputs); i++ {
		if inputs[i].Cmp(target) == 0 {
			outputs[0] = big.NewInt(int64(i - 1))
			return nil
		}
	}

	outputs[0] = big.NewInt(-1)
	return nil
}

func EqPolyOutside(api frontend.API, coords []frontend.Variable, point []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for i := range coords {
		acc = api.Mul(acc, api.Add(api.Mul(coords[i], point[i]), api.Mul(api.Sub(frontend.Variable(1), coords[i]), api.Sub(frontend.Variable(1), point[i]))))
	}
	return acc
}

func EvaluateQuadraticPolynomialFromEvaluationList(api frontend.API, evaluations []frontend.Variable, point frontend.Variable) (ans frontend.Variable) {
	inv2 := api.Inverse(2)
	b0 := evaluations[0]
	b1 := api.Mul(api.Add(api.Neg(evaluations[2]), api.Mul(4, evaluations[1]), api.Mul(-3, evaluations[0])), inv2)
	b2 := api.Mul(api.Add(evaluations[2], api.Mul(-2, evaluations[1]), evaluations[0]), inv2)
	return api.Add(api.Mul(point, point, b2), api.Mul(point, b1), b0)
}

func Exponent(api frontend.API, uapi *uints.BinaryField[uints.U64], X frontend.Variable, Y uints.U64) frontend.Variable {
	output := frontend.Variable(1)
	bits := api.ToBinary(uapi.ToValue(Y))
	multiply := frontend.Variable(X)
	for i := range bits {
		output = api.Select(bits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

func ExpandRandomness(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := frontend.Variable(1)
	for i := range len {
		res[i] = acc
		acc = api.Mul(acc, base)
	}
	return res
}

func ExpandFromUnivariate(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := base
	for i := range len {
		res[len-1-i] = acc
		acc = api.Mul(acc, acc)
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

// ParseHexFieldElement parses a hex string representing a FieldElement (little-endian)
// and converts it to a big.Int. The hex string should be 64 characters (32 bytes).
func ParseHexFieldElement(hexStr string) (*big.Int, error) {
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	reversed := make([]byte, len(bytes))
	for i, b := range bytes {
		reversed[len(bytes)-1-i] = b
	}

	result := new(big.Int)
	result.SetBytes(reversed)

	modulus := new(big.Int)
	modulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	result.Mod(result, modulus)

	return result, nil
}

// UnmarshalPublicInputs parses a JSON array of hex-encoded FieldElement strings
// and returns them as frontend.Variable slice.
func UnmarshalPublicInputs(data []byte) ([]frontend.Variable, error) {
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, err
	}

	values := make([]frontend.Variable, len(arr))
	for i, hexStr := range arr {
		value, err := ParseHexFieldElement(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input at index %d: %w", i, err)
		}
		values[i] = value
	}
	return values, nil
}
