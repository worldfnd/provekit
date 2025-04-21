# cm31_ntt

## Implementations of:

- [x] M31 field arithmetic
- [x] M31 field arithmetic using redundant representation
- [x] Complex M31 field arithmetic (using the redundant representation of M31s)
- [x] NTT (radix-8)
- [ ] NTT (any power of 2)
- [x] Benchmarks
- [x] NTT optimsations

## Benchmarks

To run benchmarks:

```bash
rustup default nightly
cargo bench
```

TODO

## Code structure

- `src/rm31.rs`: M31 field arithmetic using redundant representation.
    - See [this note by Solberg and Domb](https://github.com/ingonyama-zk/papers/blob/main/Mersenne31_polynomial_arithmetic.pdf)
      for explanations of the underlying algorithms.
- `src/cm31.rs`: Complex M31 field arithmetic using redundant representation.
- `src/ntt.rs`: The number-theoretic transform algorithm over the complex M31 field.

## NTT API

`ntt.rs` exposes:
    - `ntt(f, precomp_serialised)`: NTT for any input size. This should be the
      most efficient implementation for ARM CPUs. It is a hybrid approach which
      combines the in-place method and the Vec method, and both methods use
      precomputed twiddles.

It also contains code that was used to test and benchmark different NTT
implementations in order to find the most efficient one.

| Function | Precomputed twiddles? | Description | 8^7 | 8^8 |
|-|-|-|-|-|
| `ntt_r8_vec`        | No  | Allocates new `Vec`s per recursive iteration.                         | 759.35 ms | 7.5820 s |
| `ntt_r8_vec_p`      | Yes | Allocates new `Vec`s per recursive iteration.                         | | |
| `ntt_r8_ip`         | No  | Only allocates memory once, and reuses it to perform an in-place NTT. | | |
| `ntt_r8_ip_p`       | Yes | Only allocates memory once, and reuses it to perform an in-place NTT. | | |
| `ntt_r8_hybrid_p`   | Yes | Hybrid approach using the in-place NTT for a cache-friendly number of inputs, and the Vec method for higher layers. | | |
| `ntt_r8_hybrid_ps`  | Yes | Hybrid approach where only the in-place method uses precomputed twiddles. | | |

The above benchmarks were performed on a Raspberry Pi 5.

cargo bench --bench ntt_r8_ip && \
echo "--------------------------------------" && \
cargo bench --bench ntt_r8_ip_p && \
echo "--------------------------------------" && \
cargo bench --bench ntt_r8_hybrid_p && \
echo "--------------------------------------" && \
cargo bench --bench ntt_r8_hybrid_ps
