## Skyscraper in EVM

This is an optimized EVM implementation of SkyscraperV2 [0].

It comes in two flavors: `compress` and `compress_sigma`. The former has $σ = 1$ and the latter sets $σ$ to the value typical for Montgomery multiplication (which gives better native performance).

The gas costs are approximately 1665 and 1906 gas respectively.

* Skyscraper: 1665 gas.
* PosseidonV2: 14,934 gas [1]
* Posseidon: 13,488 gas [2]

Analysis of the EVM assembly code shows that there is at most around 200 gas that can be optimized away with manual stack management. Despite not using inline assembly and manual inlining, the current implementation is already very close to the theoretical minimum gas cost when compiled with optimizations.

[0]: https://eprint.iacr.org/2025/058
[1]: https://github.com/zemse/poseidon2-evm
[2]: https://github.com/chancehudson/poseidon-solidity
