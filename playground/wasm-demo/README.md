# ProveKit WASM Node.js Demo

A Node.js demonstration of ProveKit's WASM bindings for zero-knowledge proof generation using the **OPRF Nullifier** circuit.

## Prerequisites

1. **Noir toolchain** (v1.0.0-beta.11):
   ```bash
   noirup --version v1.0.0-beta.11
   ```

2. **Rust** with wasm32 target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

3. **wasm-pack**:
   ```bash
   cargo install wasm-pack
   ```

4. **wasm-opt**:
   ```bash
   npm install -g binaryen
   ```

## Setup

Run the setup script to build all required artifacts:

```bash
npm install

# To build with OPRF circuit
npm run setup

# To build with custom circuit
# Eg: npm run setup -- ../../noir-examples/noir-passport-examples/complete_age_check
npm run setup -- path/to/noir-circuit
```

This will:
1. Build the WASM package (`wasm-pack build`)
2. Compile the OPRF Noir circuit (`nargo compile`)
3. Prepare prover/verifier JSON artifacts (`provekit-cli prepare`)
4. Build the native CLI for verification

## Run the Demo

```bash
# To run in node environment
npm run demo

# To run in browser environment
npm run demo:web
```

The demo will:
1. Load the compiled OPRF circuit and prover artifact
2. Generate a witness using `@noir-lang/noir_js`
3. Generate a zero-knowledge proof using ProveKit WASM
4. Verify the proof using the native ProveKit CLI

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Node.js Demo                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Circuit: OPRF Nullifier                                    │
│  ├─ Merkle tree membership proof (depth 10)                 │
│  ├─ ECDSA signature verification                            │
│  ├─ DLOG equality proof                                     │
│  └─ Poseidon2 hashing                                       │
│                                                             │
│  1. Witness Generation                                      │
│     ├─ Input: Noir circuit + OPRF inputs                    │
│     └─ Tool: @noir-lang/noir_js                             │
│                                                             │
│  2. Proof Generation                                        │
│     ├─ Input: Witness + Prover.json                         │
│     └─ Tool: ProveKit WASM                                  │
│                                                             │
│  3. Verification                                            │
│     ├─ Input: Proof + Verifier.pkv                          │
│     └─ Tool: ProveKit native CLI*                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

* WASM Verifier is WIP due to tokio/mio dependency resolution
```

## Files

- `scripts/setup.mjs` - Setup script that builds all artifacts
- `src/demo.mjs` - Main demo showing WASM proof generation
- `src/wasm-loader.mjs` - Helper to load WASM module in Node.js
- `artifacts/` - Generated artifacts (circuit, prover, verifier, proofs)

## Notes

- **WASM Verifier**: Currently disabled in ProveKit WASM due to tokio/mio dependencies. 
  Verification uses the native CLI as a workaround.
- **JSON Format**: WASM bindings use JSON artifacts (not binary `.pkp`/`.pkv`) to avoid 
  compression dependencies in the browser.
- **Witness Format**: The witness map uses hex-encoded field elements as strings.
- **Circuit Complexity**: The OPRF circuit is moderately complex (~100k constraints). 
  Proof generation may take 30-60 seconds on modern hardware.

## Troubleshooting

### "command not found: nargo"
Install the Noir toolchain:
```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --version v1.0.0-beta.11
```

### "wasm-pack: command not found"
```bash
cargo install wasm-pack
```

### WASM memory errors
The OPRF circuit requires significant memory for proof generation. Increase Node.js memory limit:
```bash
NODE_OPTIONS="--max-old-space-size=8192" npm run demo
```

### Slow proof generation
The OPRF circuit is complex. On Apple Silicon (M1/M2/M3), expect ~30-60s for proof generation.
On x86_64, it may take longer. This is normal for WASM execution.
