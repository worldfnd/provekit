## Skyscraper in EVM

This is an optimized EVM implementation of SkyscraperV2 [0].

It comes in two flavors: `compress` and `compress_sigma`. The former has $σ = 1$ and the latter sets $σ$ to the value typical for Montgomery multiplication (which gives better native performance).

The gas costs are approximately 1665 and 1906 gas respectively. Compare with other 64 byte to 32 byte hash functions:

* SkyscraperV2: 1665 gas.
* SkyscraperV2 native friendly: 1906 gas.
* PosseidonV2: 14,934 gas [1]
* Posseidon: 13,488 gas [2]
* Keccak256: 266 gas
* Sha256: 495 gas
* Ripemd160: 1263 gas

Analysis of the EVM assembly code shows that there is at most around 200 gas that can be optimized away with manual stack management. Despite not using inline assembly and manual inlining, the current implementation is already very close to the theoretical minimum gas cost when compiled with optimizations.

[0]: https://eprint.iacr.org/2025/058
[1]: https://github.com/zemse/poseidon2-evm
[2]: https://github.com/chancehudson/poseidon-solidity
