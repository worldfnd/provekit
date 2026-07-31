# Native Rapidsnark Mobench adapter

This crate measures the two-proof Self passport flow with the pinned
`zkmopro/rust-rapidsnark` native wrapper:

- `passport-register`: RSA-4096 passport registration;
- `passport-disclose`: VC disclosure.

Each build enables exactly one feature so BrowserStack installs only one
proving key. The `.zkey` and frozen `.wtns` are app resources, not Rust
`include_bytes!` data. Resource loading happens in Mobench's per-iteration
setup and is excluded from `bench_passport_rapidsnark_prove`.

Use `../scripts/build-rapidsnark-mobile-ios.sh passport-disclose` or
`../scripts/build-rapidsnark-mobile-ios.sh passport-register` to build and
stage an ad-hoc-signed IPA plus its BrowserStack XCUITest bundle.
The two proofs are separate protocol stages and must not be reported as one
proof equivalent to the Noir complete-age-check circuit.
