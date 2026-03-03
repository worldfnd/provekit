# ProveKit iOS SDK - TODO

## Completed ✅

- [x] Rust FFI layer with handle-based API
- [x] Swift SDK wrapper (Prover, Verifier, Proof)
- [x] XCFramework build script
- [x] Unit tests (27 total)
- [x] Example SwiftUI app
- [x] Technical spec document
- [x] Push to remote

## In Progress 🔄

- [ ] Manual testing on real iOS device
- [ ] PR review and merge to main

## High Priority 🔴

- [ ] Real device testing (iPhone 14+)
- [ ] Memory profiling under load
- [ ] Error message improvements

## Medium Priority 🟡

### Async API
- [ ] Add `async func prove()` using Swift concurrency
- [ ] Add `Task`-based cancellation support
- [ ] Background thread execution for proof generation

### Progress Reporting
- [ ] Add progress callback protocol
- [ ] Expose proving stages from Rust FFI
- [ ] UI binding helpers for SwiftUI

### Performance
- [ ] Benchmark on older devices (iPhone 12, A14)
- [ ] Memory optimization for large circuits
- [ ] Lazy loading for prover keys

## Low Priority 🟢

### Testing & CI
- [ ] Add test fixtures to git (remove from gitignore)
- [ ] GitHub Actions workflow for SDK tests
- [ ] Code coverage reporting
- [ ] Integration tests with real circuits

### Distribution
- [ ] CocoaPods support
- [ ] Carthage support
- [ ] Swift Package Registry publishing
- [ ] Pre-built XCFramework releases

### Documentation
- [ ] API reference docs (DocC)
- [ ] Tutorial: "Your First ZK Proof on iOS"
- [ ] Troubleshooting guide
- [ ] Migration guide for updates

## Future / Out of Scope 📋

- [ ] Android SDK (Kotlin/Java)
- [ ] React Native bindings
- [ ] Flutter plugin
- [ ] WebAssembly target
- [ ] On-device circuit compilation
- [ ] Proof aggregation API
- [ ] Batch verification

## Known Issues ⚠️

| Issue | Status | Workaround |
|-------|--------|------------|
| Debug/release serialization mismatch | Won't fix | Run tests with `--release` |
| Verifier single-use | By design | Create new instance per verification |
| Synchronous API blocks UI | Planned fix | Use background queue for now |

## Notes

- XCFramework must be rebuilt when FFI changes
- Test fixtures in `noir-examples/basic-2/` are canonical
- Proof size ~1MB, keep in mind for network transfer
