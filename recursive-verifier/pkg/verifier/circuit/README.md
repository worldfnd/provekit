# pkg/verifier/circuit

This package exposes the recursive verifier circuit API. During the refactor it
serves as a façade over the legacy `app/circuit` implementation so that callers
can migrate to the new namespace before the remaining logic is relocated.

## Contents

- Circuit struct and related R1CS helpers
- High-level orchestration entry points such as `PrepareAndVerifyCircuit`
- Matrix evaluator interfaces used to select between direct and SPARK modes
