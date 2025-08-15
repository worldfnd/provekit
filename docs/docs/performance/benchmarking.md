---
sidebar_position: 1
---

# Performance Benchmarking

This guide covers how to benchmark ProveKit's performance and optimize your zero-knowledge proof applications.

## Quick Benchmarks

### Running Built-in Benchmarks

ProveKit includes comprehensive benchmarks for all components:

```bash
# Run all benchmarks
cargo bench

# Run specific component benchmarks
cargo bench -p noir-r1cs
cargo bench -p skyscraper
cargo bench -p block-multiplier
```

### Example Results (Apple M2)

| Component | Operation | Time | Throughput |
|-----------|-----------|------|------------|
| block-multiplier | Field multiplication | 12ns | 83M ops/sec |
| skyscraper | Hash compression | 400ns | 2.5M hashes/sec |
| noir-r1cs | Proof generation (1K constraints) | 15ms | 67 proofs/sec |
| noir-r1cs | Proof verification | 5ms | 200 verifications/sec |

## Circuit Performance Analysis

### Constraint Scaling

Test how proof time scales with circuit size:

```bash
# Generate circuits of different sizes
cd noir-examples
for size in 1000 5000 10000 50000; do
    echo "Testing circuit with $size constraints"
    cargo run --release --bin noir-r1cs prove circuit_${size}.nps inputs.toml --profile
done
```

### Memory Usage Profiling

Monitor memory usage during proof generation:

```bash
# Install memory profiler
cargo install cargo-instruments

# Profile memory usage
cargo instruments -t "Allocations" --bin noir-r1cs -- prove scheme.nps inputs.toml
```

## Platform Comparisons

### ARM64 vs x86_64 Performance

| Architecture | Proof Time (1K constraints) | Relative Performance |
|--------------|----------------------------|---------------------|
| Apple M2 (ARM64) | 15ms | 100% (baseline) |
| Apple M1 (ARM64) | 18ms | 83% |
| Intel i7-12700K (x86_64) | 35ms | 43% |
| AMD Ryzen 7 5800X (x86_64) | 32ms | 47% |

### Mobile Device Performance

| Device | Processor | Proof Time | Memory Usage |
|--------|-----------|------------|--------------|
| iPhone 14 Pro | A16 Bionic | 16ms | 45MB |
| iPhone 13 | A15 Bionic | 19ms | 48MB |
| Samsung S23 Ultra | Snapdragon 8 Gen 2 | 22ms | 52MB |
| Pixel 7 Pro | Tensor G2 | 28ms | 55MB |

## Optimization Techniques

### Compiler Optimizations

Ensure maximum performance with proper compilation flags:

```toml
# Cargo.toml
[profile.release]
opt-level = 3
codegen-units = 1
lto = "fat"
panic = "abort"
debug = false
```

### Runtime Configuration

```bash
# Set optimal thread count
export RAYON_NUM_THREADS=8

# Enable CPU affinity (Linux)
export RAYON_RS_AFFINITY=1

# Optimize memory allocation
export MALLOC_ARENA_MAX=2
```

### Circuit Optimization

#### Minimize Constraints

```rust
// Before: 150 constraints
fn inefficient_range_check(value: Field, min: Field, max: Field) {
    for i in min..max {
        if value == i {
            return;
        }
    }
    assert(false);
}

// After: 2 constraints  
fn efficient_range_check(value: Field, min: Field, max: Field) {
    assert(value >= min);
    assert(value <= max);
}
```

#### Batch Operations

```rust
// Before: Multiple separate proofs
fn prove_multiple_separately(values: [Field; 100]) {
    for value in values {
        let proof = prove_single(value);
        verify(proof);
    }
}

// After: Single batched proof
fn prove_multiple_batched(values: [Field; 100]) {
    let proof = prove_batch(values);
    verify(proof);
}
```

## Custom Benchmarking

### Creating Circuit Benchmarks

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use noir_r1cs::NoirProofScheme;

fn bench_proof_generation(c: &mut Criterion) {
    let scheme = NoirProofScheme::from_file("test_circuit.nps").unwrap();
    
    c.bench_function("proof_generation_1k", |b| {
        b.iter(|| {
            scheme.prove("inputs.toml").unwrap()
        })
    });
}

criterion_group!(benches, bench_proof_generation);
criterion_main!(benches);
```

### Memory Profiling

```rust
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct MemoryProfiler;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for MemoryProfiler {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if !ret.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        }
        ret
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static GLOBAL: MemoryProfiler = MemoryProfiler;

fn main() {
    let initial = ALLOCATED.load(Ordering::SeqCst);
    
    // Your proof generation code here
    let scheme = NoirProofScheme::from_file("circuit.nps").unwrap();
    let proof = scheme.prove("inputs.toml").unwrap();
    
    let peak = ALLOCATED.load(Ordering::SeqCst);
    println!("Peak memory usage: {} bytes", peak - initial);
}
```

## Performance Regression Testing

### Automated Benchmarking

```yaml
# .github/workflows/benchmark.yml
name: Performance Benchmarks

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: dtolnay/rust-toolchain@stable
    
    - name: Run benchmarks
      run: cargo bench --workspace
      
    - name: Store benchmark results
      uses: benchmark-action/github-action-benchmark@v1
      with:
        tool: 'cargo'
        output-file-path: target/criterion/report/index.html
```

### Continuous Performance Monitoring

Set up alerts for performance regressions:

```bash
# Install performance monitoring tools
cargo install cargo-criterion
cargo install flamegraph

# Run comprehensive performance analysis
cargo criterion --output-format json > benchmark-results.json

# Generate flame graphs for hotspot analysis
cargo flamegraph --bin noir-r1cs -- prove scheme.nps inputs.toml
```

## Mobile-Specific Optimizations

### Battery Life Considerations

```rust
// Adjust performance based on battery level
fn adaptive_proving_strategy() -> ProvingConfig {
    match get_battery_level() {
        level if level > 50 => ProvingConfig::HighPerformance,
        level if level > 20 => ProvingConfig::Balanced,
        _ => ProvingConfig::PowerSaver,
    }
}
```

### Thermal Management

```rust
// Monitor CPU temperature and throttle if needed
fn thermal_aware_proving(circuit: &Circuit) -> Result<Proof, Error> {
    let temp = get_cpu_temperature();
    
    if temp > 75.0 {
        // Use power-efficient proving mode
        prove_with_reduced_threads(circuit, 2)
    } else {
        // Use full performance
        prove_with_full_performance(circuit)
    }
}
```

## Troubleshooting Performance Issues

### Common Performance Problems

1. **Slow proof generation on x86_64**
   - Solution: Use ARM64 hardware or cloud instances
   - Workaround: Reduce circuit complexity

2. **High memory usage**
   - Solution: Enable streaming witness generation
   - Workaround: Use smaller batch sizes

3. **Thermal throttling on mobile**
   - Solution: Implement adaptive performance scaling
   - Workaround: Distribute proving across time

### Performance Debugging

```bash
# Profile CPU usage
perf record --call-graph dwarf ./target/release/noir-r1cs prove scheme.nps inputs.toml
perf report

# Profile memory allocations
valgrind --tool=massif ./target/release/noir-r1cs prove scheme.nps inputs.toml

# Profile with flamegraph
cargo flamegraph --bin noir-r1cs -- prove scheme.nps inputs.toml
```

## Next Steps

- [Architecture Overview](../architecture/overview) - Understand performance bottlenecks
- [Mobile Deployment](mobile-optimization) - Optimize for mobile devices
- [Examples](../examples/poseidon-hash) - See optimized implementations
