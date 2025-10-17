# pkg/verifier/types

Shared data structures used across the verifier stack live here. The package
contains domain representations for WHIR parameters, Merkle witnesses, SPARK
transcript hints, and configuration structs that drive the recursive verifier.

These types are now owned by the `pkg/verifier` namespace and re-exported by
`app/circuit` for backwards compatibility during the ongoing refactor.
