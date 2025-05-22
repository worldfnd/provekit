# Contributing to ProveKit

Thanks for your interest in contributing! This project welcomes bug reports, feature requests, code contributions, documentation improvements, and suggestions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Project Setup](#project-setup)
- [Style and Guidelines](#style-and-guidelines)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Issues](#reporting-issues)
- [Community](#community)

---

## Code of Conduct

This project adheres to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). By participating, you agree to uphold these standards.

---

## How to Contribute

You can contribute in several ways:

- Report bugs and issues
- Suggest new features or enhancements
- Improve documentation
- Fix typos or improve examples
- Submit code via pull requests

Check the [open issues](https://github.com/worldfnd/ProveKit/issues) and look for those labeled:

- `good first issue`
- `help wanted`
- `documentation`

---

## Project Setup

To get started with development:

```bash
# Clone the repo
git clone https://github.com/worldfnd/ProveKit
cd ProveKit

# Install Rust (if you haven't)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and test
cargo build
cargo test

# Run linter and formatter
cargo fmt
cargo clippy

# Run benchmarks
cargo bench
```

## Style and Guidelines

*	Follow Rust’s official style guide — use `cargo fmt`.
*	Lint with `cargo clippy` and fix warnings before submitting.
*	Prefer `Result<T, E>` over panicking, use `thiserror` to create `Error` types.
*	Include doc comments (`///`) for all public items.
*	Write tests for new functionality.
*	Use feature flags for optional dependencies or integrations.

⸻

## Submitting a Pull Request

1.	Fork the repository
2.	Create a new branch: `git checkout -b your-feature`
3.	Commit your changes: `git commit -m 'Add your feature'`
4.	Push to your fork: `git push origin your-feature`
5.	Open a pull request and describe your changes

We’ll review your PR and may suggest changes. Thank you for your contribution!

---

## Reporting Issues

When filing an issue, please include:

*	A clear and descriptive title
*	Steps to reproduce (if applicable)
*	Expected vs actual behavior
*	Environment (Rust version, OS, etc.)
*	Any relevant logs or screenshots

Use the appropriate issue template if available.

## Community

For questions, discussions, and general feedback, join us on:

*	[Slack](https://world.slack.com/archives/C083C5JM8QH) (Requires invitation)
