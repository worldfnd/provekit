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

## Code structure

- `src/rm31.rs`: M31 field arithmetic using redundant representation.
    - See [this note by Solberg and Domb](https://github.com/ingonyama-zk/papers/blob/main/Mersenne31_polynomial_arithmetic.pdf)
      for explanations of the underlying algorithms.
- `src/cm31.rs`: Complex M31 field arithmetic using redundant representation.
- `src/ntt.rs`: The number-theoretic transform algorithm over the complex M31 field.

## Finding the fastest NTT implementation

The following table shows the approaches that I benchmarked in order to find
the fastest NTT implementation.

`ntt_r8_vec` and `ntt_r8_vec_p` are straightforward implementations of the
divide-and-conquer algorithm (the former does not precompute twiddle factors,
and the latter does), but they allocate new `Vec`s with each recursive
implementation, resulting in some performance overhead.

`ntt_r8_ip` and `ntt_r8_ip_p` are in-place implementations of the NTT
algorithm. Even though they do not allocate new memory, they suffer a great
deal from cache misses.

`ntt_r8_hybrid_ps` and `ntt_r8_hybrid_p` are hybrid implementations that
allocate new `Vec`s only for the higher-level recursive iterations, and use the
in-place algorithm for the lowest level. The size of the lowest level is
defined by the `NTT_BLOCK_SIZE_FOR_CACHE` variable in `ntt.rs`.

`ntt_r8_hybrid_p` is the fastest, as it uses precomputed twiddles for both the
higher-level and lowest-level iterations. `ntt_r8_hybrid_ps` only uses
precomputed twiddles for the lowest-level iteration.

| Function | Precomputed twiddles? | Description | 8^7 | 8^8 |
|-|-|-|-|-|
| `ntt_r8_vec`        | No  | Allocates new `Vec`s per recursive iteration.                         | 759.35 ms | 7.5820 s |
| `ntt_r8_vec_p`      | Yes | Allocates new `Vec`s per recursive iteration.                         | 452.63 ms | 4.6361 s |
| `ntt_r8_ip`         | No  | Only allocates memory once, and reuses it to perform an in-place NTT. | 955.20 ms | 11.734 s |
| `ntt_r8_ip_p`       | Yes | Only allocates memory once, and reuses it to perform an in-place NTT. | 926.22 ms | 13.321 |
| `ntt_r8_hybrid_p`   | Yes | Hybrid approach using the in-place NTT for a cache-friendly number of inputs, and the Vec method for higher layers. | 320.61 | **3.3997 s** |
| `ntt_r8_hybrid_ps`  | Yes | Hybrid approach where only the in-place method uses precomputed twiddles. | 450.03 ms | 4.8309 s |

The following functions use `ntt_r8_hybrid_p` under the hood to perform the NTT
for inputs of length `8^k * 2` and `8^k * 4` respectively.

- `ntt_r8_s2_hybrid_p`
- `ntt_r8_s4_hybrid_p`

### Hardware

The above benchmarks were performed on a Raspberry Pi 5. No multithreading was used.

The output of `lscpu` on the Raspberry Pi 5 is as follows:

```
Architecture:             aarch64
  CPU op-mode(s):         32-bit, 64-bit
  Byte Order:             Little Endian
CPU(s):                   4
  On-line CPU(s) list:    0-3
Vendor ID:                ARM
  Model name:             Cortex-A76
    Model:                1
    Thread(s) per core:   1
    Core(s) per cluster:  4
    Socket(s):            -
    Cluster(s):           1
    Stepping:             r4p1
    CPU(s) scaling MHz:   62%
    CPU max MHz:          2400.0000
    CPU min MHz:          1500.0000
    BogoMIPS:             108.00
    Flags:                fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop a
                          simddp
Caches (sum of all):      
  L1d:                    256 KiB (4 instances)
  L1i:                    256 KiB (4 instances)
  L2:                     2 MiB (4 instances)
  L3:                     2 MiB (1 instance)
NUMA:                     
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-3
Vulnerabilities:          
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Not affected
  Retbleed:               Not affected
  Spec rstack overflow:   Not affected
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; __user pointer sanitization
  Spectre v2:             Mitigation; CSV2, BHB
  Srbds:                  Not affected
  Tsx async abort:        Not affected
```
