package types

// KeccakDigest stores a 32-byte digest in little-endian order.
type KeccakDigest struct {
	KeccakDigest [32]uint8
}

// Fp256 encodes a BN254 field element using four 64-bit limbs.
type Fp256 struct {
	Limbs [4]uint64
}

// Path represents a Merkle authentication path and associated metadata.
type Path[Digest any] struct {
	LeafSiblingHash Digest
	AuthPath        []Digest
	LeafIndex       uint64
}

// FullMultiPath groups multiple proofs together for batched verification.
type FullMultiPath[Digest any] struct {
	Proofs []Path[Digest]
}

// ProofObject is a thin wrapper around statement evaluations.
type ProofObject struct {
	StatementValuesAtRandomPoint []Fp256 `json:"statement_values_at_random_point"`
}
