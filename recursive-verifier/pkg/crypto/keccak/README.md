# pkg/crypto/keccak

A thin gnark-compatible Keccak sponge implementation. It wraps the standard
permutation API and exposes absorb/squeeze helpers consumed by the verifier.
