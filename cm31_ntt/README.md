# cm31_ntt

## Implementations of:

- [x] M31 field arithmetic
- [x] M31 field arithmetic using redundant representation [x] Complex M31 field arithmetic (using the redundant representation of M31s)
- [x] NTT (radix-8)
- [x] Benchmarks
- [ ] Optimsations


## Benchmarks

To run benchmarks:

```bash
rustup default nightly
cargo bench
```


### Radix-8 NTT block 
At the time of writing, the results on a Raspberry Pi 5 are:

```
     Running benches/ntt_32768.rs (target/release/deps/ntt_32768-380c493e74327e27)
Gnuplot not found, using plotters backend
ntt_radix_8             time:   [19.014 ms 19.032 ms 19.059 ms]
                        change: [+102.58% +102.92% +103.27%] (p = 0.00 < 0.05)
Found 3 outliers among 10 measurements (30.00%)
  2 (20.00%) low mild
  1 (10.00%) high mild

     Running benches/ntt_block_8.rs (target/release/deps/ntt_block_8-3f25dbef695374ee)
Gnuplot not found, using plotters backend
ntt_block_8             time:   [194.70 ns 194.70 ns 194.70 ns]
                        change: [+157.39% +157.56% +157.68%] (p = 0.00 < 0.05)
Found 719 outliers among 10000 measurements (7.19%)
  2 (0.02%) low severe
  14 (0.14%) low mild
  395 (3.95%) high mild
  308 (3.08%) high severe
```

### Radix-8 NTT with and without twiddle factor precomputation

At the time of writing, the results for a 2^24-sized NTT on a Raspberry Pi 5 are:

```
NTT (2^24)/size 16777216 without precomputation
                        time:   [8.7177 s 8.7209 s 8.7238 s]
                        change: [-1.5060% -1.3964% -1.3036%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking NTT (2^24)/size 16777216 with precomputation: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 57.0s.
Benchmarking NTT (2^24)/size 16777216 with precomputation: Collecting 10 samples in estimated 57.050 s (10 iteratio
NTT (2^24)/size 16777216 with precomputation
                        time:   [5.7222 s 5.7275 s 5.7319 s]
                        change: [+0.4652% +0.5621% +0.6504%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 2 outliers among 10 measurements (20.00%)
  1 (10.00%) low severe
  1 (10.00%) low mild
```
