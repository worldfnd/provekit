---
sidebar_position: 1
---

# Installation

This guide will help you install ProveKit and all its dependencies on your development machine.

## Prerequisites

### System Requirements

- **Operating System**: macOS (ARM64) or Linux (x86_64/ARM64)
- **Rust**: 1.85+ 
- **Node.js**: 18.0+ (for Noir)
- **Go**: 1.19+ (for Gnark integration)

### Architecture Support

ProveKit is optimized for ARM64 but supports:
- ✅ **ARM64 (Apple Silicon, ARM servers)** - Full optimization
- ⚠️ **x86_64** - Basic support, reduced performance

## Installing Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify your Rust version:
```bash
rustc --version
# Should show 1.85 or later
```

## Installing Noir Toolchain

ProveKit requires a specific version of the Noir toolchain:

```bash
# Install Noir toolchain
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
source ~/.bashrc

# Install the required version
noirup --version nightly-2025-05-28
```

Verify Noir installation:
```bash
nargo --version
# Should show: nargo version = 0.32.0+nightly-2025-05-28
```

## Installing Go (Optional)

For Gnark integration and recursive proofs:

```bash
# macOS
brew install go

# Ubuntu/Debian
sudo apt install golang-go

# Verify
go version
# Should show: go version go1.19+ ...
```

## Cloning ProveKit

```bash
git clone https://github.com/worldfnd/ProveKit.git
cd ProveKit
```

## Building ProveKit

Build all workspace members:

```bash
cargo build --release
```

This will:
- Compile all Rust crates
- Generate optimized ARM64 assembly (if on ARM64)
- Build CLI tools and libraries

### Verify Installation

Run the test suite to verify everything works:

```bash
cargo test
```

Run benchmarks (optional):
```bash
cargo bench
```

## CLI Tools

After building, you'll have access to these CLI tools:

```bash
# Noir to R1CS compiler and prover
./target/release/noir-r1cs --help
```

## Troubleshooting

### Common Issues

**Noir version mismatch:**
```bash
noirup --version nightly-2025-05-28
```

**Missing dependencies:**
```bash
# macOS
brew install llvm

# Ubuntu/Debian  
sudo apt install build-essential clang llvm
```

### Getting Help

If you encounter issues:

1. Check [GitHub Issues](https://github.com/worldfnd/ProveKit/issues)
2. Ask in [Discussions](https://github.com/worldfnd/ProveKit/discussions)

## Next Steps

Once installed, proceed to the [Quick Start Guide](./quick-start) to build your first proof!
