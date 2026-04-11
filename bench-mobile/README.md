# bench-mobile

Mobile benchmarks for ProveKit's monolithic passport circuit using
[mobench](https://github.com/worldcoin/mobile-bench-rs).

## Benchmarks

The crate exposes four benchmark functions:

- `bench_mobile::bench_passport_complete_age_check_prepare`
- `bench_mobile::bench_passport_complete_age_check_prove`
- `bench_mobile::bench_passport_complete_age_check_verify`
- `bench_mobile::bench_passport_complete_age_check_e2e`

These use embedded fixtures from `bench-mobile/fixtures/complete_age_check/`:

- `complete_age_check.json`
- `Prover.toml`

## Local usage

Install the Noir toolchain expected by the repo:

```bash
noirup --version v1.0.0-beta.11
```

Refresh the checked-in Noir artifact fixture:

```bash
cd noir-examples/noir-passport-monolithic/complete_age_check
nargo compile --skip-brillig-constraints-check --force
cp target/complete_age_check.json ../../../bench-mobile/fixtures/complete_age_check/complete_age_check.json
```

Build mobile artifacts:

```bash
cargo-mobench build --target ios --release --crate-path bench-mobile
cargo-mobench build --target android --release --crate-path bench-mobile
```

## BrowserStack device profiles

PR benchmarks run the smoke profile by default:

- Android: `Google Pixel 7-13.0`
- iOS: `iPhone 16 Pro-18`

Manual workflow dispatches can still select the triad profile:

- Android:
  - `Vivo Y21-11.0`
  - `Google Pixel 7-13.0`
  - `Samsung Galaxy S24-14.0`
- iOS:
  - `iPhone 14-16.3`
  - `iPhone 15-17`
  - `iPhone 16 Pro-18`

The worst-device profile currently targets:

- Android: `Vivo Y21-11.0`
- iOS: `iPhone 14-16.3`

The sticky PR comment is updated in place using the `<!-- mobench-summary -->`
marker so each rerun replaces the previous report.
