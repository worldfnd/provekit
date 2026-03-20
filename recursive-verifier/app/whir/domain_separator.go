package whir

import (
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"
)

// bn254Modulus is the BN254 scalar field prime:
// 21888242871839275222246405745257275088548364400416034343698204186575808495617
var bn254Modulus, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10,
)

// poseidon2EngineID is the 32-byte hash engine identifier for our Poseidon2
// implementation, matching POSEIDON2 in rust/gkr/src/poseidon/hash_engine.rs.
var poseidon2EngineID = [32]byte{
	0xab, 0x4c, 0x81, 0x0f, 0x79, 0xdd, 0xf2, 0xa5,
	0x4e, 0x81, 0x73, 0x1f, 0x97, 0x08, 0x23, 0x6a,
	0xcf, 0x5c, 0xc2, 0xcc, 0x35, 0xe9, 0xc4, 0x57,
	0xa4, 0x35, 0x37, 0xdc, 0x01, 0x23, 0x6b, 0xb7,
}

// engineIDCBOR is a custom type that serializes a [32]byte as a CBOR array of
// 32 unsigned integers, matching serde's serialize_tuple behaviour for [u8; 32].
// (Go's cbor library would default to a byte string, which is wrong.)
type engineIDCBOR [32]byte

func (e engineIDCBOR) MarshalCBOR() ([]byte, error) {
	arr := make([]uint64, 32)
	for i, b := range e {
		arr[i] = uint64(b)
	}
	return cbor.Marshal(arr)
}

// MarshalCBOR serializes FoldingFactor matching ciborium's Rust enum encoding:
//   - VariableFirst=false  → {"Constant": factor}
//   - VariableFirst=true   → {"ConstantFromSecondRound": [firstRound, factor]}
func (ff FoldingFactor) MarshalCBOR() ([]byte, error) {
	if ff.VariableFirst {
		inner := map[string][2]uint64{
			"ConstantFromSecondRound": {uint64(ff.FirstRound), uint64(ff.Factor)},
		}
		return cbor.Marshal(inner)
	}
	inner := map[string]uint64{
		"Constant": uint64(ff.Factor),
	}
	return cbor.Marshal(inner)
}

// MarshalCBOR serializes SoundnessType as a CBOR string matching ciborium's
// unit enum variant encoding (e.g. UniqueDecoding → "UniqueDecoding").
func (s SoundnessType) MarshalCBOR() ([]byte, error) {
	var name string
	switch s {
	case UniqueDecoding:
		name = "UniqueDecoding"
	case ProvableList:
		name = "ProvableList"
	case ConjectureList:
		name = "ConjectureList"
	default:
		name = "UniqueDecoding"
	}
	return cbor.Marshal(name)
}

// cborSessionString returns the CBOR encoding of the session string,
// matching ciborium's serialization of &"keccacheck-input-coxmmitment".
func cborSessionString() []byte {
	data, err := cbor.Marshal("keccacheck-input-coxmmitment")
	if err != nil {
		panic("CBOR marshal of session string failed: " + err.Error())
	}
	return data
}

// fromLeBytesModOrder interprets a byte slice as a little-endian integer and
// reduces it modulo the BN254 scalar field, replicating ark_ff's
// Fr::from_le_bytes_mod_order.
func fromLeBytesModOrder(b []byte) *big.Int {
	// Reverse to big-endian for big.Int
	be := make([]byte, len(b))
	for i, v := range b {
		be[len(b)-1-i] = v
	}
	n := new(big.Int).SetBytes(be)
	return n.Mod(n, bn254Modulus)
}

// ComputeDomainSeparator computes the 3 field elements that spongefish's
// DomainSeparator absorbs during WHIR verifier initialisation:
//
//	[0]: first 32 bytes of SHA3-512(CBOR(ProtocolConfig))  → Fr
//	[1]: last 32 bytes of SHA3-512(CBOR(ProtocolConfig))   → Fr
//	[2]: SHA3-256(CBOR(session_string))                    → Fr
func ComputeDomainSeparator(cfg ProtocolConfig) [3]*big.Int {
	// Protocol ID: SHA3-512 of CBOR-encoded ProtocolParameters → 64 bytes
	protocolCBOR, err := cbor.Marshal(cfg)
	if err != nil {
		panic("CBOR marshal of ProtocolConfig failed: " + err.Error())
	}
	protocolHash := sha3.Sum512(protocolCBOR)

	// Session ID: SHA3-256 of CBOR-encoded session string → 32 bytes
	sessionCBOR := cborSessionString()
	sessionHash := sha3.Sum256(sessionCBOR)

	return [3]*big.Int{
		fromLeBytesModOrder(protocolHash[:32]),
		fromLeBytesModOrder(protocolHash[32:]),
		fromLeBytesModOrder(sessionHash[:]),
	}
}
