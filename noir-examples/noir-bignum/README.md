# noir-bignum

An optimized big number library for Noir.

noir-bignum evaluates modular arithmetic for large integers of any length.

BigNum instances are parametrised by a struct that satisfies BigNumParamsTrait.

Multiplication operations for a 2048-bit prime field cost approx. 930 gates.

bignum can evaluate large integer arithmetic by defining a modulus() that is a power of 2.

## High level overview

This library provides modular arithmetic operations for big numbers. The Noir std library provides integers up to 128 bits and a field type up to 254 bits; this library supports arbitrary length numbers.

A number of pre-defined bignum and finite field types are provided. If you need a bignum or finite field that's not on this list, this repo also provides the tools you'll need to generate your own.

See `./src/lib.nr` for the list of exported bignums.

See `./src/fields/` for files which shows how those bignums were created; you can copy this approach to generate your own bignums.

More details about this library are described in the rest of this document, this is just a quick high level overview. 

To start using the library:

If the bignum you need is in the pre-defined list, import it and use it:

```rust
use dep::bignum::U256;
```

If the bignum you need is not in the pre-defined list, you'll need to create it:
1. Define or import a **parameter set** with info about your modulus
2. Define the correct **type** for your big number

Instructions on how to do this can be found below.

Step 2 depends on when you know your modulus; this can be either at compile-time or runtime. Use the correct type for your situation:
* `BigNum`, if modulus is known at compile-time
* `RuntimeBigNum`, if modulus is known at runtime. Note: the number of bits of the modulus must be known at compile-time. 

Both types have mostly the same methods available to them. 

For the arithmetic operations it is important to notice the difference between constrained and unconstrained functions. The overloaded operators `==,+,-,*,/` are all _constrained_ methods and are expensive. The recommended thing to do is perform multiple unconstrained functions (e.g `__add`, `__sub` etc) and then constrain with `evaluate_quadratic_expression`. Find further explanation and examples below. 

## Noir Version Compatibility

This library is tested with all stable releases since 1.0.0-beta.0 as well as nightly.

Refer to [Noir's docs](https://noir-lang.org/docs/getting_started/installation/) for installation steps.

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```
[dependencies]
bignum = { tag = "v0.4.2", git = "https://github.com/noir-lang/noir-bignum" }
```

### Import a pre-defined bignum:

Add imports at the top of your Noir code, for example:

```rust
use dep::bignum::U256;
```

### Create a custom bignum:

> We use U256 as an illustrative example, even though it's actually a pre-defined bignum.

Use the paramgen tool to generate your bignum's params (see below). Then define your custom bignum from those params:

```rust
use dep::bignum::fields::U256::U256Params;
use dep::bignum::BigNum;

// Define (compile-time) BigNum type
// number of limbs, number of bits of modulus, parameter set
type U256 = BigNum<3, 257, U256Params>;
```

### Quick example: Addition in U256

A simple 1 + 2 = 3 check in 256-bit unsigned integers. Note that for performing multiple arithmetic operations up to degree 2 it is recommended to use `evaluate_quadratic_expression` (see explanation below). 

```rust
use dep::bignum::U256;

fn main() {
    let one = U256::from_slice([1, 0, 0]);
    let two = U256::from_slice([2, 0, 0]);
    let three = U256::from_slice([3, 0, 0]);
    assert((one + two) == three);
}
```


## Types

### `BigNum` / `RuntimeBigNum` definition

A BigNum is a number modulo `modulus` and is represented as an array of 120-bit limbs in little endian format. When the `modulus` is known at compile-time, use this type:

```rust
pub struct BigNum<let N: u32, let MOD_BITS: u32, Params> {
    pub limbs: [Field; N],
}
```
- `N` is the number of limbs needed to represent the number. Each limb is a `Field`, which contains max 120 bits. The field type has 254 bits of space and by only using 120 bits, there is space for multiplications and additions without overflowing. 
- `MOD_BITS` is the number of bits needed to represent the modulus.
- `Params` is a parameter set (`BigNumParams`) associated with the big number. More information below.

The actual value of a BigNum can be calculated by multiplying each limb by an increasing power of $2^{120}$. For example `[1,20,300]` represents $1 \cdot 2^{120\cdot0} + 20 \cdot 2^{120 \cdot 1} + 300 \cdot 2^{120 \cdot 2}$. We say that the BigNum is represented in radix- $2^{120}$. 

When `modulus` is known at runtime, the type is slightly different, but the representation of the actual number in limbs works the same way:

```rust

pub struct RuntimeBigNum<let N: u32, let MOD_BITS: u32> {
    pub limbs: [Field; N],
    pub params: BigNumParams<N, MOD_BITS>,
}
```

### `BigNumParams` definition

To define a `BigNum` or `RuntimeBigNum`, you need to provide a `BigNumParams`. For compile-time known moduli you can use predefined parameter sets from this library or define custom parameters using [this tool](https://github.com/noir-lang/noir-bignum-paramgen). See below for an overview of the available predefined parameter sets, as well as an example of how to generate your own. For runtime known moduli, provide the needed parameters through witnesses. 

`BigNumParams` contains the following:

- `modulus` represents the BigNum modulus, encoded as an array of `Field` elements that each encode 120 bits of the modulus. The first array element represents the least significant 120 bits. For convenience, the parameter set contains various representations of the same modulus; `modulus`, `modulus_u60` and `modulus_u60_x4`

- `redc_param` is equal to `(1 << (2 * Params::modulus_bits())) / modulus` . This must be computed outside of the circuit and provided either as a private witness or hardcoded constant. (computing it via an unconstrained function would be very expensive until noir witness computation times improve)

- `double_modulus` is derived via the method `compute_double_modulus` in `runtime_bignum.nr`. If you want to provide this value as a compile-time constant (see `fields/bn254Fq.nr` for an example), follow the algorithm `compute_double_modulus` as this parameter is _not_ structly 2 \* modulus. Each limb except the most significant limb borrows 2^120 from the next most significant limb. This ensure that when performing limb subtractions `double_modulus.limbs[i] - x.limbs[i]`, we know that the result will not underflow

- `has_multiplicative_inverse`, a boolean indicating whether the elements have a multiplicative inverse or not


## `BigNum` / `RuntimeBigNum` methods

The methods that are available on the types `BigNum` and `RuntimeBigNum` are almost the same. This section discusses these methods and uses "bignum" to indicate both types.

The library offers all standard modular arithmetic operations, constrained and unconstrained. **Important:** When evaluating more than 1 arithmetic operations, it is recommended to perform unconstrained arithmetic operations and then constrain using `evaluate_quadratic_expression`. 

Furthermore, there are some convenient methods to manipulate a bignum or make assertions about it. 

### Unconstrained functions

All the constrained arithmetic methods have their unconstrained counterpart and there is an unconstrained method for exponentiation. The unconstrained methods are prefixed with `__`:
- `__add`
- `__sub`
- `__mul`
- `__neg`
- `__div`
  - Note: this method is only available for fields, i.e if all elements have a multiplicative inverse. If this is not the case, use `__udiv`
- `__udiv`/`__udiv_mod`
  - Note: only use if you're not working with a field
- `__pow`

> **Note:** `__div`, `__udiv` and `__pow` are expensive due to requiring modular exponentiations during witness computation. It is worth modifying witness generation algorithms to minimize the number of modular exponentiations required. (for example, using batch inverses, mentioned below)

Use the following unconstrained operations only when working with a field (otherwise the inverse is not defined):

- `__invmod`, returns inverse of element
- `__batch_invert`, input is fixed size array. Returns inverses of all elements
- `__batch_invert_slice`, input is dynamically sized array. Returns inverses of all elements

Other useful unconstrained functions:
- `__derive_from_seed`, only use for test purposes. Not cryptographically secure
- `__is_zero`
- `__eq`

### Constrained functions

Note: try to avoid using these constrained methods if possible, for example by calling multiple unconstrained arithmetic functions and then constrain them with `evaluate_quadratic_expression` (explained in next section).

Constrained arithmetic operations. These perform the expected arithmetic operations and reduce the result modulo `modulus`:
- `add`
- `sub`
- `mul`
- `neg`
- `div` - Expensive!
  - Note: this method is only available for Fields, i.e if all elements have a multiplicative inverse. If this is not the case, use `udiv`
- `udiv`/`udiv_mod` - Expensive!
  - Note: only use if you're not working with a Field
- `umod` - Expensive!
  - Integer modular reduction which uses `udiv`

These methods can be used using operators (`+`, `-`, `*`, `/`). 

> **Note:** `div`, `udiv` and `umod` are expensive due to requiring modular exponentiations during witness computation. It is worth modifying witness generation algorithms to minimize the number of modular exponentiations required. (for example, using batch inverses)

Other constrained functions:
- `new`, returns a bignum with value 0
- `one`, returns a bignum with value 1
- `modulus`, returns `modulus` from the parameters
- `modulus_bits`, returns nr of bits from the parameters
- `num_limbs`, returns N, the number of limbs needed to represent the bignum for the current parameters
- `evaluate_quadratic_expression`, more explanation below
- `validate_in_range`, validates the bignum doesn't have more bits than `modulus_bits`
- `validate_in_field(val)`, validates `val` < `modulus`
- `assert_is_not_equal`, assert 2 bignums are distinct
- `eq`, also available with operator `==`
- `get(idx)`, return value of limbs `idx` (this is a field)
- `set_limb(idx, value)`, set limbs `idx` to new value
- `conditional_select(lhs, rhs, predicate)`, if `predicate` is 0 returns `lhs`, else if `predicate` is 1 returns `rhs` 
- `to_le_bytes`, returns the little-endian byte representation of a bignum

### `evaluate_quadratic_expression`

For a lower gatecount and thus better performance perform multiple unconstrained arithmetic operations and then constrain them at once using `evaluate_quadratic_expression`.

E.g. if we wanted to compute `a * b + (c + d) * e + f = g`, instead of calling all five arithmetic operations in their constrained form, compute `g` via unconstrained functions and then constrain it with `evaluate_quadratic_expression`. 

Unconstrained functions `__mul, __add, __sub, __div, __pow` can be used to compute witnesses that can then be fed into `evaluate_quadratic_expression`.

The method `evaluate_quadratic_expression` has the following interface:

```rust
    fn evaluate_quadratic_expression<let LHS_N: u64, let RHS_N: u64, let NUM_PRODUCTS: u64, let ADD_N: u64>(
        self,
        lhs_terms: [[BN; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs_terms: [[BN; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        linear_terms: [BN; ADD_N],
        linear_flags: [bool; ADD_N]
    );
```

`NUM_PRODUCTS` represents the number of multiplications being summed.

`LHS_N, RHS_N` represents the number of `BigNum` objects being summed in the left and right operands of each product. 

`ADD_N` represents the number of `BigNum` objects being added

The flag parameters `lhs_flags, rhs_flags, add_flags` define whether an operand in the expression will be negated. 

For example, for the earlier example we wanted to calculate `a * b + (c + d) * e + f = g`. To constrain this, we pass `a * b + (c + d) * e + f - g = 0` to `evaluate_quadratic_expression`. The parameters then become:
- `NUM_PRODUCTS` = 2. The products are `a * b` and `(c + d) * e`
- `LHS_N` = 2, `RHS_N` = 1. For the left hand side the first multiplication has 1 operand and the other 2, so take the upper limit and pad with zeroes
- `ADD_N` = 2. The linear terms are `f` and `-g`


To constrain the example, first calculate `g = a * b + (c + d) * e + f` in unconstrained functions.
```rust
// First product term a * b
let t0 = a.__mul(b);
// Second product term (c + d) * e
let t1 = (c.__add(d)).__mul(e); 
let g = t0.__add(t1).__add(f);
```



Then define the terms and flags to constrain `a * b + (c + d) * e + f - g = 0` and call `evaluate_quadratic_expression`. 
```rust
// (a + 0) * b
let lhs_terms = [[a, BigNum::new()], [c, d]];
let lhs_flags = [[false, false], [false, false]];
// (c + d) * e 
let rhs_terms = [[b], [e]];
let rhs_flags = [[false], [false]];
// + f + (-g)
let add_terms = [f, g];
let add_flags = [false, true];

BigNum::evaluate_quadratic_expression(lhs_terms, lhs_flags, rhs_terms, rhs_flags, linear_terms, linear_flags);
```

#### Example usage evaluate_quadratic_expression

In the base field of Ed25519, which is the integers mod $2^{255}-19$, perform simple arithmetic operations `(x1 * x2) + x3` and assert this equals `expected`. 

```rust
use dep::bignum::BigNum;
use dep::bignum::fields::ed25519Fq::ED25519_Fq_Params;

// Prime field mod 2^255-19
type Fq = BigNum<3, 255, ED25519_Fq_Params>;

// Check that (x1 * x2) + x3 equals `expected`
fn main(x1: Fq, x2: Fq, x3: Fq, expected: Fq) {
    // Step 1: calculate res = (x1 * x2) + x3 in unconstrained functions
    let res = x1.__mul(x2).__add(x3);

    // Step 2: Constrain (x1 * x2) + x3 - res == 0 mod 2^255-19
    // (until now we have value res, but "unchecked")

    // `evaluate_quadratic_expression` takes:
    // (1) x1, `false` sign flag
    // (2) x2, `false` sign flag
    // (3)
    //  - x3, `false` sign flag
    //  - res, `true` sign flag
    // Combines to: (x1 * x2) + x3 + (-res)
    BigNum::evaluate_quadratic_expression(
        [[x1]],
        [[false]],
        [[x2]],
        [[false]],
        [x3, res],
        [false, true],
    );

    // Step 3: check res equals `expected`
    assert(res == expected); // Equality operation on BigNums
}
```

See `bignum_test.nr` for more examples.

## Custom or predefined parameter set

There are predefined parameter sets located in `bignum/fields` of this library. Alternatively, you can create a new parameter set by populating a `BigNumParams`. 

### Predefined Unsigned Integers

BigNum supports operations over unsigned integers, with predefined types for 256, 384, 512, 768, 1024, 2048, 4096 and 8192 bit integers. Keep in mind these are not Fields.

All arithmetic operations are supported including integer div and mod functions (make sure to use udiv, umod). Bit shifts and comparison operators are not yet implemented.

```rust
use dep::bignum::fields::U256::U256Params;
use dep::bignum::BigNum;

type U256 = BigNum<3, 257, U256Params>;

fn foo(x: U256, y: U256) -> U256 {
    x.udiv(y)
}
```

### Predefined Fields

This library includes the follow field presets:

| Curve       | Base Field Instance                | Scalar Field Instance              |
|-------------|------------------------------------|------------------------------------|
| [BLS12-377](https://eprint.iacr.org/2020/351)   | `BLS12_377_Fq_Params`            | `BLS12_377_Fr_Params`            |
| [BLS12-381](https://electriccoin.co/blog/new-snark-curve/)   | `BLS12_381_Fq_Params`            | `BLS12_381_Fr_Params`            |
| [BN254](https://zips.z.cash/protocol/protocol.pdf)   | `BN254_Fq_Params`                    | (Scalar field is the native field in Noir) |
| [Curve25519](https://cr.yp.to/ecdh/curve25519-20060209.pdf)  | `ED25519_Fq_Params`              | `ED25519_Fr_Params`              |
| [MNT4-753](https://eprint.iacr.org/2014/595)    | `MNT4_753_Fq_Params`             | `MNT4_753_Fr_Params`             |
| [MNT6-753](https://eprint.iacr.org/2014/595)    | `MNT6_753_Fq_Params`             | `MNT6_753_Fr_Params`             |
| [Pallas](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)     | `Pallas_Fr_Params` | `Pallas_Fq_Params` |
| [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1) | `Secp256k1_Fq_Params`            | `Secp256k1_Fr_Params`            |
| [Secp256r1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) | `Secp256r1_Fq_Params`            | `Secp256r1_Fr_Params`            |
| [Secp384r1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) | `Secp384r1_Fq_Params`            | `Secp384r1_Fr_Params`            |

Feature requests and/or pull requests welcome for missing fields you need.


### Create a new parameter set for custom modulus

TODO: the paramgen tool is not up to date for `BigNum` version >= `0.4`, an issue has been created for this [here](https://github.com/noir-lang/noir-bignum-paramgen/issues/4). This section should be adjusted after this fix.

The easiest way to generate everything you need for a parameter set is to use [this tool](https://github.com/noir-lang/noir-bignum-paramgen). 

For example, after cloning and building the tool, for a `modulus` of 1024 bits for RSA run `./target/release/paramgen instance <modulus> RSA1024_example > out.txt`. This prints the parameter set to `out.txt`. Since this is not a field, also add: 
```rust
fn has_multiplicative_inverse() -> bool { false }
```
to the traits implementations for the parameter set. 

#### Provide parameters for runtime known modulus

For a modulus that is known at runtime, the needed parameters in `BigNumParams` can be provided as witnesses. In the program, use `RuntimeBigNum`, which only requires the number of limbs and number of bits of modulus at the type definition.  

```rust
use bignum::fields::bn254Fq::BN254_Fq_Params;

// Notice how we don't provide the params here, because we're pretending they're
// not known at compile-time, for illustration purposes.
type My_RBN = RuntimeBigNum<3, 254>;

fn main() {
    let params = BN254_Fq_Params::get_params(); // replace this with your own parameters, provided as witnesses

    // Notice how we feed the params in, because we're pretending they're not
    // known at compile-time.
    let one: My_RBN = RuntimeBigNum::from_array(params, [1, 0, 0]);
    let two: My_RBN = RuntimeBigNum::from_array(params, [2, 0, 0]);
    let three: My_RBN = RuntimeBigNum::from_array(params, [3, 0, 0]);

    assert((one + two) == three);
}
```

## Benchmarks v0.3.0

Benchmarks can be run using [this repo](https://github.com/hashcloak/noir-bigint-bench/). 

A full benchmark report based on that repo can be found [here](https://docs.google.com/spreadsheets/d/1KBc6mhMZ4iQYIZhsyF8E6-juhob7mM94sBKqVKS-v-8/edit?gid=0#gid=0). Below a few numbers are repeated. 

Number of gates:
| BigNum |  100 mult  | 100 add/sub |
|:-----|:--------:|:------:|
| **U256**   | 8507 | 5510 |
| **U1024**   |  31960  | 11832 |
| **U2048**   | 86935 | 20857 |

Proving time, UP = UltraPlonk, UH = UltraHonk, in milliseconds:

| BigNum |  100 mult UP  | 100 add UP | 100 mult HP  | 100 add HP |
|:-----|:--------:|:------:|:--------:|:------:|
| **U256**   | 548.6 | 313.1 | 329.8 | 208 | 
| **U1024**   |  1026.1  | 498.4 | 614.1 | 292 | 
| **U2048**   | 3101.2 | 842.3 | 1404.4 | 436.9 | 


## Benchmarks v0.4.x

TODO

## Additional usage example

Elliptic curve point doubling using `evaluate_quadratic_expression`:

```rust
use dep::bignum::fields::bn254Fq::BN254_Fq_Params;
use dep::bignum::BigNum;

type Fq = BigNum<3, 254, BN254_Fq_Params>;

fn example_ecc_double(x: Fq, y: Fq) -> (Fq, Fq) {
    // Step 1: construct witnesses
    // lambda = 3*x*x / 2y
    let mut lambda_numerator = x.__mul(x);
    lambda_numerator = lambda_numerator.__add(lambda_numerator.__add(lambda_numerator));
    let lambda_denominator = y.__add(y);
    let lambda = lambda_numerator / lambda_denominator;
    // x3 = lambda * lambda - x - x
    let x3 = lambda.__mul(lambda).__sub(x.__add(x));
    // y3 = lambda * (x - x3) - y
    let y3 = lambda.__mul(x.__sub(x3)).__sub(y);

    // Step 2: constrain witnesses to be correct using minimal number of modular reductions (3)
    // 2y * lambda - 3*x*x = 0
    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[y,y]],
        [[false, false]],
        [x,x,x],
        [true, true, true]
    );
    // lambda * lambda - x - x - x3 = 0
    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3,x,x],
        [true, true, true]
    );
    // lambda * (x - x3) - y = 0
     BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x, x3]],
        [[false, true]],
        [y],
        [true]
    );
    (x3, y3)
}
```
