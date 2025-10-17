# pkg/crypto/polynomial

Polynomial evaluation helpers used inside the recursive verifier circuit.
Functions here are pure and operate on `frontend.Variable` slices, making them
easy to unit test and share across packages.
