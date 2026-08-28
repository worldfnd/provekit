# Native Rapidsnark WebAuthn Mobench adapter

This adapter proves the pinned `privacy-ethereum/webauth-circom` assertion
fixture with the standard SnarkJS Groth16 zkey and the pinned
`zkmopro/rust-rapidsnark`-derived native wrapper.

It registers prove, verify, and end-to-end functions. Circom witness
generation is measured once by the matching Mopro Arkworks adapter; it is
shared circuit work and is not attributed to Rapidsnark.
