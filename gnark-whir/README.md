# WHIR proof verifier

A command-line application performing a recursive verification of a zero-knowledge proof using [WHIR](https://eprint.iacr.org/2024/1586.pdf).

## Usage

```bash
go run . [flags]
```

### Flags

- `--config` Path to the JSON configuration file containing verifier circuit parameters (default: `../noir-examples/poseidon-rounds/params_for_recursive_verifier`)
- `--r1cs` Path to the R1CS JSON file describing the constraint system of the inner circuit (default: `../noir-examples/poseidon-rounds/r1cs.json`)
- `--ccs` Optional path to store the constraint system object of the verifier circuit (default: empty, don't serialize)
- `--pk` Optional path to load the Proving Key (PK) that will be used to generate proof for the verifier circuit. If not provided, PK will be generated unsafely (default: empty, generate own key)
- `--vk` Optional path to load the Verifying Key (VK) that will be used to prove the verifier circuit. If not provided, VK will be generated unsafely (default: empty, generate own key)
