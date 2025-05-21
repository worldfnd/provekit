# Project Roadmap

This document outlines the planned development path for the project. It helps contributors and users understand the project's direction and priorities.

## Vision

> A zero-knowledge proof system for large proofs on small devices.

---

## Status Overview

| Milestone              | Status          | Target Version | ETA         |
|------------------------|-----------------|----------------|-------------|
| Prototype              | ✅ Done         | v0.1.0         | 2025-04-01  |
| MVP                    | 🟡 In Progress  | v0.2.0         | 2025-06-01  |
| Release                | ⬜ Planned      | v1.0.0         | 2025-08-01  |
| Mersenne 31            | ⬜ Planned      | v1.1.0         | TBD         |
| Folding / Recursion    | ⬜ Backlog      | v2.0.0         | TBD         |

---

## Milestone Details

### Milestone: Prototype (v0.1.0)
- [x] Compile Noir circuit containing only AssertZeros to R1CS.
- [x] Create satisfying witness
- [x] Proof using WHIR-GR1CS with Skyscraper.
- [x] Recursively verify in Gnark.

---

### Milestone: MVP (v0.2.0)
- [ ] Support most Noir opcodes.
- [ ] Proofs are zero knowledge.
- [ ] Switch to Skyscraper V2.
- [ ] Optimized for performance and memory.
- [ ] Recursion service.

---

### Milestone: Release (v1.0.0)
- [ ] Use sparse evaluation proof in Gnark recursion.
- [ ] Review interfaces, documentation and test coverage.
- [ ] Code audit.
- [ ] Publish crates, deploy services.

---

### Milestone: Mersenne 31 (v1.0.0)
- [ ] Add M31 support to Noir.
- [ ] Adapt GR1CS to M31.
- [ ] Publish crates, deploy services.

---

### Future Ideas (Backlog)
- [ ] Parallelization in witness generation.
- [ ] Implement recursion by direct verification.
- [ ] Implement folding.
- [ ] Optimize for repeated submatrices in GR1CS.
- [ ] Support for running as a cosnark.
- [ ] Consider Binary Fields.

---

## Contribution

Want to help? Check out the [Contributing Guide](CONTRIBUTING.md) and look for issues labeled `good first issue` or `help wanted`.
