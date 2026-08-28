# Historical Barretenberg 0.87 native mobile adapter

This beta.11/v0.87 adapter is retained as compatibility and feasibility
evidence. It is not the backend reported by the final cross-device campaign,
which uses the pinned beta.19/Barretenberg 4.2 line described in
[`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md). Do not cite this document as
the publication benchmark method.

This directory is an exact-version native adapter for the campaign's Noir
`1.0.0-beta.11` / Barretenberg `v0.87.0` lane. It does **not** use or relabel
Mopro's beta.19 / Barretenberg 4.2 backend.

The adapter is deliberately fail closed:

- the upstream source revision is pinned in `upstream.lock.json`;
- device builds use the upstream static `barretenberg` CMake target;
- CRS initialization uses `init_file_crs_factory`, whose native factory has
  `allow_download=false`;
- package assets and the native library must match `package-manifest.json`;
- Rust's `native-v087` feature will not link unless
  `BB_V087_MOBILE_LIB_DIR` contains the exact library;
- every C++ exception is caught at the C ABI boundary, and every returned
  allocation has one matching free function.

The upstream v0.87 release publishes macOS/Linux executables and WASM, but no
iOS or Android libraries. The source does define a static `barretenberg`
archive. `build-barretenberg-mobile.sh` therefore builds the pinned source
directly and supplies explicit Apple/Android CMake toolchains.

## Build feasibility

Start with the host build before spending time on mobile packaging:

```bash
benchmarks/v1/scripts/build-barretenberg-mobile.sh host
```

Then build a device archive:

```bash
benchmarks/v1/scripts/build-barretenberg-mobile.sh ios
ANDROID_NDK_HOME=/path/to/ndk \
  benchmarks/v1/scripts/build-barretenberg-mobile.sh android
```

The build script never changes upstream source. A source incompatibility,
missing SDK/NDK, or unsupported standard-library call is a hard failure.

## Package contract

The device package contains the native library, a complete local CRS, and the
frozen beta.11 `circuit.json`, `witness.gz`, and retained canonical proof
fixtures for Passport, WebAuthn, and OPRF. Create it with:

```bash
bun benchmarks/v1/scripts/package-barretenberg-mobile.ts \
  --platform ios \
  --adapter-library target/v1-benchmarks/barretenberg-mobile/ios-v3/install/lib/libbarretenberg_v087_mobile.a \
  --upstream-library target/v1-benchmarks/barretenberg-mobile/ios-v3/install/lib/libbarretenberg.a \
  --crs /absolute/path/to/complete/crs \
  --output target/v1-benchmarks/barretenberg-mobile/packages/ios
```

The generated manifest records SHA-256, byte length, source revision, backend
version, Noir version, platform, and relative packaged path for every asset.
The Rust wrapper verifies the whole manifest before calling native code.

## Timing boundary

The package exposes four phases for each workload:

- `witness`: beta.11 ACVM witness generation; intentionally unavailable until
  the existing beta.11 ACVM is wired into this crate;
- `prove`: native Barretenberg only; circuit, witness, and CRS preparation are
  outside the timed call;
- `verify`: native Barretenberg only; proof/VK reads and verification are timed;
- `e2e`: native prove followed by native verify; witness generation remains a
  separately reported phase.

No workload is publishable until a wrapper-generated proof verifies with the
canonical `bb v0.87.0`, a canonical proof verifies through the wrapper, and a
tampered proof, modified public inputs, and mismatched VK are all rejected.

## Retained host feasibility result

On 2026-07-27, canonical `bb v0.87.0` proved the frozen OPRF beta.11
bytecode/witness and verified both its generated proof and the retained web
proof against the generated VK. Both proofs were 14,592 bytes and were
byte-for-byte identical:

```text
sha256 569fc5a96b07d60ccc3f59dabd0088d711b5aa7a3b392e7fb40609238712c625
```

A one-bit mutation in the generated proof was rejected. This establishes
beta.11/v0.87 host compatibility and validates the public-input field encoding;
it does not establish a successful mobile link or device run.

## Retained cross-build feasibility

Pinned source commit `9081b0ed38c43c120afb7c80f8f6cd418ca5ad70`
successfully produced both archives on 2026-07-27:

| Target | Adapter SHA-256 | Upstream archive SHA-256 |
| --- | --- | --- |
| arm64 iOS 15+ | `015079faa86d7955ef489ca749c37415659ab1a0e4e78ba839cd9ff667b5497e` | `1925d738990001a36cf95200cbeb1f4401d487f3032ba8a5ce6dcc70110752a8` |
| AArch64 Android API 28+ | `a7c26cdb936769a1d1537794422d57d49653c5083332d8024fcf72bc73ff1361` | `686a0e37dd699a9f92a67d7608a3b6fceaa9e7f131e281f4e94cd4d39c342c40` |

The Android adapter's extracted object is ELF64 AArch64, the iOS archive is
arm64 Mach-O, and both export all seven expected `bb_v087_*` entry points.
Android API 28 is the honest minimum because v0.87 calls `aligned_alloc` and
`getrandom`, which are unavailable in older Android NDK API surfaces.

Both post-hook archives also pass a real Rust target link. Mobench's required
iOS simulator slice uses an explicit fail-closed shim; only the independently
linked arm64 device slice contains Barretenberg. Release IPA/AAB payload
validation confirms all 21 runtime assets byte-for-byte before upload.

The original iOS failure traced to upstream's CLI-oriented `gunzip` subprocess,
which is unavailable in app sandboxes. The Android null crash initially looked
consistent with the same path, but the v3 result below shows another Android
cause remains. The v3 mobile compatibility header decompresses immutable
`.gz` inputs in-process with zlib. The generated iOS app also links `-lz`, and
generated Android apps enforce API 28.

iPhone SE 2022 / iOS 15.4 subsequently completed all nine prove, verify, and
end-to-end functions with one warmup and five samples. The medians are retained
in `results/run-30041758043/barretenberg-mobile-release/ios-v3-summary.json`.
The beta.11 ACVM witness phase remains unavailable.

Android is still blocked. The v3 Pixel 7 / Android 13 OPRF app loaded the exact
1/5 benchmark spec and then the isolated native worker received `SIGSEGV` at
address zero before emitting a sample. Do not widen Android until that
remaining target-specific crash is fixed.

These hashes are feasibility evidence from this checkout, not release pins:
rebuilds may differ because static archives contain build metadata. The package
manifest records the exact bytes actually linked into a benchmark app.
