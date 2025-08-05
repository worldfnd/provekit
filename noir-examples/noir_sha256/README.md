# SHA256 Hashing Library

This package contains the SHA256 hashing interface, formerly in the Noir standard library.

## Noir Version Compatibility

This library is tested to work as of Noir v0.36.0.

## Benchmarks

Benchmarks are ignored by `git` and checked on pull-request. As such, benchmarks may be generated
with the following command.

```bash
# execute the following
./scripts/build-gates-report.sh
```

The benchmark will be generated at `./gates_report.json`.

## Installation

In `Nargo.toml`, add the version of this library desired to install the dependency:

```toml
[dependencies]
sha256 = { tag = "v0.1.0", git = "https://github.com/noir-lang/sha256" }
```
