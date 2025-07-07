module reilabs/whir-verifier-circuit

go 1.23.3

require (
	github.com/consensys/gnark v0.11.0
	github.com/consensys/gnark-crypto v0.14.1-0.20241217131346-b998989abdbe
	github.com/reilabs/gnark-nimue v0.0.5
	github.com/reilabs/gnark-skyscraper v0.0.0-20250529113204-fda06626925b
	github.com/reilabs/go-ark-serialize v0.0.0-20241120151746-4148c0ca17e3
)

// Remove replace directive for gnark-nimue when changes are pushed to gnark-nimue
replace github.com/reilabs/gnark-nimue => ../../gnark-nimue

require (
	github.com/bits-and-blooms/bitset v1.17.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.24 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/google/pprof v0.0.0-20241122213907-cbe949e5a41b // indirect
	github.com/ingonyama-zk/icicle v1.1.0 // indirect
	github.com/ingonyama-zk/iciclegnark v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/ronanh/intcomp v1.1.0 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
