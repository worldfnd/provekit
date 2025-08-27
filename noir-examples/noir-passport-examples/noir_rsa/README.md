# noir_rsa

Optimized Noir library that evaluates RSA signatures.

This library uses <https://github.com/noir-lang/noir-bignum> as a dependency.

## Noir version compatibility

This library is tested with all Noir stable releases from v1.0.0-beta.0.

## Benchmarks

The benchmarking source code and its details can be found in [this repository](https://github.com/hashcloak/noir_rsa_bench).

For the results, "UP" stands for UltraPlonk and "UH" stands for UltraHonk.

The benchmark results for the verification of one signature are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (UP) [ms]** | **Avg. proving time (UH) [ms]** |
| -------------- | ---------------- | ------------------------------- | ------------------------------- |
| 1024           | 2204             | 234.8                           | 181                             |
| 2048           | 7131             | 345.6                           | 261.9                           |

Also, the results for the verification of 10 signatures are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (UP) [ms]** | **Avg. proving time (UH) [ms]** |
| -------------- | ---------------- | ------------------------------- | ------------------------------- |
| 1024           | 21516            | 970.9                           | 514.4                           |
| 2048           | 63821            | 1801.7                          | 964.2                           |

The benchmarks were executed using a laptop with Intel(R) Core(TM) i7-13700H CPU and 32 GB of RAM.

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```
[dependencies]
noir_rsa = { tag = "v0.8.1", git = "https://github.com/zkpassport/noir_rsa" }
```

## Usage

See tests in `lib.nr` for examples.

## End-to-end example

### Generate RSA signature

To verify an RSA signature, you first need a signature.

Depending on the application you are building, you might be expecting user signatures from existing signing services (e.g. emails, passports, git commits), or you might be building the ability for users to sign directly in your application.

Either way, you are free to choose how you collect / generate the signatures as long as they comply with the PKCS#1 v1.5 RSA cryptography specifications (ex. by following <https://docs.rs/rsa/latest/rsa/#pkcs1-v15-signatures>).

You need to install Rustup and run it in order to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup
```

Then clone this repo, move into the `signature_gen` folder, and run `cargo run`, optionally with the message to sign:

```bash
cd signature_gen
cargo run # or cargo run -- --msg "hello world!"
```

The program prints the hash of the message, the RSA signature, and the BigNumber instance you should use. These are parsed to a compatible format, ready to be used in the Noir RSA library.

#### Use it in your Noir test

Move into the `example` folder. Replace the hardcoded values with result of the previous step. Since you know the size of your key, you can import those types from the rsa lib:

```diff
-    let hash: [u8; 32] = etc...
-    let signature: BN2048 = etc...
-    let bn = etc...
+    let hash: [u8; 32] = paste from terminal...
+    let signature: BN2048 = paste from terminal...
+    let bn = paste from terminal...
```

Run the test:

```bash
nargo test
```

#### Prove it

Run `nargo check` to initialize `Prover.toml`:

```bash
nargo check
```

Run the same `cargo` command, but with the `--toml` flag:

```bash
cargo run -- --msg "hello world!" --toml
```

Copy and paste it to Prover.toml. Example:

```toml
bn = [
    [
        "0xcba7415fa9d2192d5cdac144f95f75",
        "0x2b46305b91eeed9e9a992076172b46",
        "0x76c9e6e0a407e67bc0a3ee276927d7",
        "0x0d0eaa3b10ab266755ea20c44619f6",
        "0x4b040e9ab1acb761b1ab9a60309ee4",
        "...etc"
    ]
]
```

Then execute it, and prove it i.e. with barretenberg:

```bash
nargo execute rsa
bb prove -b ./target/example.json -w ./target/rsa.gz -o ./target/proof
```

### Verify it

To verify, we need to export the verification key:

```bash
bb write_vk -b ./target/example.json -o ./target/vk
```

And verify:

```bash
bb verify -k ./target/vk -p ./target/proof
```
