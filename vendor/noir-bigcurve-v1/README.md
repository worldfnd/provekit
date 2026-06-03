# noir_bigcurve

noir_bigcurve is a @noir-lang library that evaluates operations over elliptic curves instantiated with an arbitrary prime field.

noir_bigcurve uses the [noir-bignum](https://github.com/zac-williamson/noir-bignum) library to evalaute arbitrary prime field arithmetic.

This library is a work in progress and likely full of bugs!

# Overview

`noir_bigcurve` make use of `noir-bignum` to optimally evaluate group operations using a minimal number of modular reductions. Runtime lookup tables are also used to reduce the number of group operations required when evaluating scalar multiplications

# Usage

See `bigcurve_test.nr` for some ways in which the library can be used.

Complete elliptic curve operations can be evalauted using `BigCurve::add`, `BigCurve::sub` `BigCurve::mul` and `BigCurve::msm_with_hint`.

`msm_with_hint` requires the generation of an `AffineTranscript` object in an unconstrained function. See `bigcurve_test.nr` for how this is done.

The most efficient method to evaluate curve operations is `BigCurve::evaluate_linear_expression` (TODO: Brillig bug means this method does not currently work!)

# Future work

- When performing MSMs, utilize the Montgomery Ladder to minimize the number of field operations (see `batch_mul` in `barretenberg/src/stdlib/biggroup` for example implementation)
- `ScalarField` is not properly constrained when constructed from a `BigNum` object
- [x] Add tests for curves that have a nonzero `a` parameter
- [x] Add hash to curve method
- Add method to check point is in prime-order subgroup for curves with a cofactor
- Parametrise and test with a degree-2 extension field instead of `BigNum`
- [x] Add curve parameters for commonly used curves (BN254, BLS12-381, MNT4, MNT6, Pasta, Vella, Secp256K1, Secp256R1)
- Add support for curve endomorphisms where applicable (if base field and scalar field both contain cube roots of unity, we can reduce the number of point doublings required for an MSM in half)

# FAQ

Q: What's up with the Jacobian points and the transcript objects?
A: To minimize witness generation time (currently the bottleneck due to Brillig VM) we evaluate ECC operations over Jacobian coordinates in an unconstrained function, in order to efficiently batch-compute the modular inverses required to constrain ECC operations over Affine coordinates (which is more constraint-efficient)
