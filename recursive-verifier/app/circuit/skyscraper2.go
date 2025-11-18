package circuit

import (
	"math/big"
)

// BN254 scalar field modulus
var bn254Modulus = new(big.Int)

// SIGMA_INV constant for Skyscraper
var sigmaInv = new(big.Int)

// Round constants for Skyscraper
var roundConstants [18]*big.Int

func init() {
	// BN254 modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
	bn254Modulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// SIGMA_INV: 9915499612839321149637521777990102151350674507940716049588462388200839649614
	sigmaInv.SetString("9915499612839321149637521777990102151350674507940716049588462388200839649614", 10)

	// Initialize round constants from the Rust implementation
	rcHex := [][4]uint64{
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x903c4324270bd744, 0x873125f708a7d269, 0x081dd27906c83855, 0x276b1823ea6d7667},
		{0x7ac8edbb4b378d71, 0xe29d79f3d99e2cb7, 0x751417914c1a5a18, 0x0cf02bd758a484a6},
		{0xfa7adc6769e5bc36, 0x1c3f8e297cca387d, 0x0eb7730d63481db0, 0x25b0e03f18ede544},
		{0x57847e652f03cfb7, 0x33440b9668873404, 0x955a32e849af80bc, 0x002882fcbe14ae70},
		{0x979231396257d4d7, 0x29989c3e1b37d3c1, 0x12ef02b47f1277ba, 0x039ad8571e2b7a9c},
		{0xb5b48465abbb7887, 0xa72a6bc5e6ba2d2b, 0x4cd48043712f7b29, 0x1142d5410fc1fc1a},
		{0x7ab2c156059075d3, 0x17cb3594047999b2, 0x44f2c93598f289f7, 0x1d78439f69bc0bec},
		{0x05d7a965138b8edb, 0x36ef35a3d55c48b1, 0x8ddfb8a1ac6f1628, 0x258588a508f4ff82},
		{0x1596fb9afccb49e9, 0x9a7367d69a09a95b, 0x9bc43f6984e4c157, 0x13087879d2f514fe},
		{0x295ccd233b4109fa, 0xe1d72f89ed868012, 0x2e9e1eea4bc88a8e, 0x17dadee898c45232},
		{0x9a8590b4aa1f486f, 0xb75834b430e9130e, 0xb8e90b1034d5de31, 0x295c6d1546e7f4a6},
		{0x850adcb74c6eb892, 0x07699ef305b92fc3, 0x4ef96a2ba1720f2d, 0x1288ca0e1d3ed446},
		{0x01960f9349d1b5ee, 0x8ccad30769371c69, 0xe5c81e8991c98662, 0x17563b4d1ae023f3},
		{0x6ba01e9476b32917, 0xa1cb0a3add977bc9, 0x86815a945815f030, 0x2869043be91a1eea},
		{0x81776c885511d976, 0x7475d34f47f414e7, 0x5d090056095d96cf, 0x14941f0aff59e79a},
		{0xbc40b4fd8fc8c034, 0xbb7142c3cce4fd48, 0x318356758a39005a, 0x1ce337a190f4379f},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	}

	for i := range rcHex {
		roundConstants[i] = limbsToBigInt(rcHex[i])
	}
}

// Convert [4]uint64 limbs to big.Int (little-endian)
func limbsToBigInt(limbs [4]uint64) *big.Int {
	result := new(big.Int)

	// limbs[0] + limbs[1]<<64 + limbs[2]<<128 + limbs[3]<<192
	result.SetUint64(limbs[0])

	temp := new(big.Int)
	temp.SetUint64(limbs[1])
	temp.Lsh(temp, 64)
	result.Add(result, temp)

	temp.SetUint64(limbs[2])
	temp.Lsh(temp, 128)
	result.Add(result, temp)

	temp.SetUint64(limbs[3])
	temp.Lsh(temp, 192)
	result.Add(result, temp)

	return result.Mod(result, bn254Modulus)
}

// Convert big.Int to [4]uint64 limbs
func bigIntToLimbs(val *big.Int) [4]uint64 {
	// Ensure value is positive and reduced
	v := new(big.Int).Set(val)
	v.Mod(v, bn254Modulus)

	limbs := [4]uint64{}
	mask := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF)

	for i := 0; i < 4; i++ {
		temp := new(big.Int).And(v, mask)
		limbs[i] = temp.Uint64()
		v.Rsh(v, 64)
	}

	return limbs
}

// Field modular addition
func fieldAdd(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, bn254Modulus)
}

// Field modular multiplication
func fieldMul(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	return result.Mod(result, bn254Modulus)
}

// Field squaring
func fieldSquare(a *big.Int) *big.Int {
	return fieldMul(a, a)
}

// S-box function for bar operation
func sbox(v byte) byte {
	notV := ^v
	rotLeft1 := (notV << 1) | (notV >> 7)
	rotLeft2 := (v << 2) | (v >> 6)
	rotLeft3 := (v << 3) | (v >> 5)

	xor := v ^ (rotLeft1 & rotLeft2 & rotLeft3)
	return (xor << 1) | (xor >> 7) // rotate left by 1
}

// Bar function: cyclic rotate bytes + s-box
func bar(x *big.Int) *big.Int {
	// Convert to 32 bytes (little-endian)
	bytes := make([]byte, 32)
	xBytes := x.Bytes()

	// x.Bytes() returns big-endian, we need little-endian
	for i := 0; i < len(xBytes) && i < 32; i++ {
		bytes[i] = xBytes[len(xBytes)-1-i]
	}

	// Cyclic rotate by 16 bytes
	rotated := make([]byte, 32)
	copy(rotated[:16], bytes[16:])
	copy(rotated[16:], bytes[:16])

	// Apply s-box to each byte
	for i := range rotated {
		rotated[i] = sbox(rotated[i])
	}

	// Convert back to big.Int (little-endian)
	result := new(big.Int)
	for i := 31; i >= 0; i-- {
		result.Lsh(result, 8)
		result.Or(result, new(big.Int).SetUint64(uint64(rotated[i])))
	}

	return result.Mod(result, bn254Modulus)
}

// SS round (square-sigma round)
func ss(round int, l, r *big.Int) (*big.Int, *big.Int) {
	// r += l^2 * sigma_inv + rc[round]
	lSquared := fieldSquare(l)
	term := fieldMul(lSquared, sigmaInv)
	term = fieldAdd(term, roundConstants[round])
	r = fieldAdd(r, term)

	// swap(l, r)
	l, r = r, l

	// r += l^2 * sigma_inv + rc[round+1]
	lSquared = fieldSquare(l)
	term = fieldMul(lSquared, sigmaInv)
	term = fieldAdd(term, roundConstants[round+1])
	r = fieldAdd(r, term)

	// swap(l, r)
	l, r = r, l

	return l, r
}

// BB round (bar-bar round)
func bb(round int, l, r *big.Int) (*big.Int, *big.Int) {
	// r += bar(l) + rc[round]
	barL := bar(l)
	r = fieldAdd(r, barL)
	r = fieldAdd(r, roundConstants[round])

	// swap(l, r)
	l, r = r, l

	// r += bar(l) + rc[round+1]
	barL = bar(l)
	r = fieldAdd(r, barL)
	r = fieldAdd(r, roundConstants[round+1])

	// swap(l, r)
	l, r = r, l

	return l, r
}

// Permute function: 9 rounds of alternating ss and bb
func permute(l, r *big.Int) (*big.Int, *big.Int) {
	l, r = ss(0, l, r)
	l, r = ss(2, l, r)
	l, r = ss(4, l, r)
	l, r = bb(6, l, r)
	l, r = ss(8, l, r)
	l, r = bb(10, l, r)
	l, r = ss(12, l, r)
	l, r = ss(14, l, r)
	l, r = ss(16, l, r)
	return l, r
}

// SkyscraperCompress: Main compression function
// Takes two field elements (as [4]uint64 limbs) and returns compressed hash
func SkyscraperCompress(left, right [4]uint64) [4]uint64 {
	l := limbsToBigInt(left)
	r := limbsToBigInt(right)

	t := new(big.Int).Set(l)
	l, _ = permute(l, r)
	result := fieldAdd(l, t)

	return bigIntToLimbs(result)
}

// SkyscraperCompressFp256: Compress two Fp256 field elements
func SkyscraperCompressFp256(left, right Fp256) Digest {
	leftLimbs := left.Limbs
	rightLimbs := right.Limbs

	resultLimbs := SkyscraperCompress(leftLimbs, rightLimbs)

	// Convert result limbs to Digest (32 bytes, little-endian)
	var digest Digest
	for i := 0; i < 4; i++ {
		limb := resultLimbs[i]
		for j := 0; j < 8; j++ {
			digest.Digest[i*8+j] = byte(limb & 0xFF)
			limb >>= 8
		}
	}

	return digest
}

// HashLeafData: Hash multiple Fp256 elements to create a leaf digest
// This iteratively compresses pairs of elements
func HashLeafData(leafData []Fp256) Digest {
	if len(leafData) == 0 {
		panic("Cannot hash empty leaf data")
	}

	// Start with first element
	currentLimbs := leafData[0].Limbs
	// Iteratively compress with remaining elements
	for i := 1; i < len(leafData); i++ {
		currentLimbs = SkyscraperCompress(currentLimbs, leafData[i].Limbs)
	}

	var digest Digest
	// Convert to Digest
	for i := 0; i < 4; i++ {
		limb := currentLimbs[i]
		for j := 0; j < 8; j++ {
			digest.Digest[i*8+j] = byte(limb & 0xFF)
			limb >>= 8
		}
	}

	return digest
}

// HashTwoDigests: Hash two digests together
func HashTwoDigests(left, right Digest) Digest {
	// Convert digests to [4]uint64 limbs (little-endian)
	leftLimbs := [4]uint64{}
	rightLimbs := [4]uint64{}

	for i := 0; i < 4; i++ {
		var limb uint64
		for j := 0; j < 8; j++ {
			limb |= uint64(left.Digest[i*8+j]) << (8 * j)
		}
		leftLimbs[i] = limb
	}

	for i := 0; i < 4; i++ {
		var limb uint64
		for j := 0; j < 8; j++ {
			limb |= uint64(right.Digest[i*8+j]) << (8 * j)
		}
		rightLimbs[i] = limb
	}

	resultLimbs := SkyscraperCompress(leftLimbs, rightLimbs)

	var digest Digest
	for i := 0; i < 4; i++ {
		limb := resultLimbs[i]
		for j := 0; j < 8; j++ {
			digest.Digest[i*8+j] = byte(limb & 0xFF)
			limb >>= 8
		}
	}

	return digest
}

func DigestToFieldElement(d Digest) *big.Int {
	var result = new(big.Int)

	for i := 31; i >= 0; i-- {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(d.Digest[i])))
	}

	result.Mod(result, bn254Modulus)
	return result
}
