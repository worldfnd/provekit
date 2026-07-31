# Passport and OPRF semantic parity contract

This document defines the statements that may be compared in the parity
campaign. It supersedes workload-name matching: two rows are directly
comparable only when they implement the same profile below, use the same
logical fixture, expose the same public outputs, and pass the same positive and
negative tests.

The original V1 results remain historical closest-analogue measurements. They
must not be relabelled as parity results.

## Source baseline

| Implementation | Immutable revision | Role |
| --- | --- | --- |
| Self passport Circom | `15b167e3543a9dff1dbb16fcf71a45fe4625cf9e` | Production behavior to preserve |
| World ID Protocol Circom | `85aeeef539961cae5a63de794997b507a5975717` | Production OPRF behavior to preserve |
| TACEO `oprf-nr` Noir | `808f3c795b57963dd58ef282ccd61022ef39c285` | Primitive implementation, not the target application statement |
| ProveKit V1 Passport Noir | campaign worktree revision plus frozen artifact hash | Starting point for the matched Noir port |

Before implementation, compare the pinned production sources with their
current upstream heads. Every accepted upstream semantic change gets its own
test vector and is recorded in the parity fixture manifest. Performance-only
or unrelated product changes are not silently folded into the campaign.

Upstream audit on 2026-07-31:

- Self upstream HEAD is still `15b167e3`; the pinned Passport source is
  current.
- World ID Protocol upstream HEAD is `590b47d5`, but the files under
  `circom/client_side_proofs` are byte-for-byte unchanged from `85aeeef5`.
  The pinned Circom OPRF statement is therefore current.
- TACEO upstream HEAD is `6c74828b` (release line `v2.0.0`). It strengthens
  point types and subgroup handling, derives the blinded response inside the
  circuit instead of trusting a separately supplied point, and updates Noir
  APIs. The matched Noir port must start from this behavior, not the older
  `v0.1.0-beta.1` benchmark example. TACEO remains a primitive source; World
  ID's O1/O2 application statements remain the parity target.

## Passport

### Why the old rows are not comparable

The existing Noir `complete_age_check` is one proof that checks age range,
passport expiry, DG1 inclusion in the SOD, the DSC signature on the signed
attributes, and the CSCA signature on the DSC certificate. Its current fixture
uses RSA exponent 65537, a 2048-bit DSC modulus, and a 4096-bit CSCA modulus.

The selected Self flow uses
`register_sha256_sha256_sha256_rsa_65537_4096` and `vc_and_disclose`. The first
proof verifies a SHA-256 / RSA PKCS#1 v1.5 / exponent-65537 / 4096-bit passport
signature and a DSC/CSCA-derived registry leaf, then creates a commitment. The
second proves commitment membership, expiry and the selected age predicate;
it also contains disclosure, OFAC, scoped-nullifier, and application binding
machinery. Adding or averaging their timings does not create an equivalent
measurement.

### P1: matched monolithic passport statement

P1 is the primary proof-system comparison. Implement one isolated benchmark
circuit in each language with exactly these checks:

1. The private DG1 bytes encode the frozen date of birth and expiry date.
2. SHA-256 of the same DG1 byte slice occurs at the frozen offset in the same
   signed eContent/SOD fixture.
3. The same signed-attributes digest is verified with RSA PKCS#1 v1.5,
   exponent 65537 and a 4096-bit DSC modulus in both circuits.
4. The DSC identity is authorized against the same frozen public registry
   root and path. For P1, use Self's production registry-leaf construction in
   both languages; do not compare it with a raw public CSCA key or an extra
   CSCA-certificate signature check.
5. Passport expiry is checked against the same public calendar date.
6. The holder is at least the same public minimum age. Maximum age is disabled
   in both circuits for P1 because Self's production disclosure statement has
   no corresponding maximum-age predicate.
7. The public outputs are the registry root, current date, minimum age, and a
   fixture identifier/hash agreed by both implementations. No implementation-
   specific commitment or nullifier is part of P1.

The shared fixture therefore needs a real or synthetic internally consistent
4096-bit RSA passport chain accepted by Self, plus a byte-for-byte derived Noir
input. Reusing the current Noir dummy fixture is forbidden: its DSC key is only
2048 bits and its Unix-timestamp date encoding differs from Self's YYMMDD byte
encoding.

### P2: production lifecycle profile

P2 measures Self's real two-proof registration/disclosure lifecycle and a Noir
port of that lifecycle. It is reported as two separately measured stages and
as a measured end-to-end session; it is never represented by a sum of medians.

- Registration: passport signature and data integrity, registry authorization,
  and the exact Self commitment/nullifier construction.
- Disclosure: commitment-tree membership, expiry, minimum-age predicate,
  selected disclosure, application scope and scoped nullifier.
- OFAC selectors and country-list policy must either be enabled identically in
  both implementations or disabled identically by a separately named profile.

Poseidon-based commitment and nullifier operations must use the same Poseidon
variant, width, state layout, constants, output element and domain separators.
Calling both functions `Poseidon` is not sufficient evidence of parity.

### Passport parity tests

- Both witness encoders derive their inputs from one canonical fixture.
- Both implementations expose identical public values after normalizing only
  representation (for example YYMMDD bytes versus a documented packed field).
- Changing DOB across the threshold fails both proofs.
- An expired passport fails both proofs.
- Mutating DG1, signed attributes, signature, DSC key, registry path/root,
  current date or minimum age fails both proofs.
- P2 additionally rejects a mutated commitment path, scope and nullifier input.

## OPRF

### Why the old rows are not comparable

TACEO's `oprf_example` intentionally combines query generation and final
response verification in one demonstration circuit. It proves knowledge of a
Poseidon2 preimage commitment and uses the short `OPRF` output domain
separator.

World ID uses two application proofs. The query binds World ID PK registry
membership, an EdDSA-Poseidon2 authorization signature, `mt_index`, `rp_id`,
`action`, nonce and a non-zero in-range blinding scalar. The nullifier proof
repeats query validity and additionally checks a credential signature and
validity window, DLog equality, response subgroup membership and unblinding,
then derives a World ID nullifier and optional identity commitment. These are
different statements even when both use BabyJubJub and Poseidon2.

### O1: matched World ID query statement

Port `OprfQuery` to an isolated Noir circuit without deleting production
checks. Match:

- the exact Poseidon2 permutation/constants and capacity-element convention;
- domain separator `b"World ID Query"`;
- `query = Poseidon2(mt_index, rp_id, action)` using the same state layout and
  output element;
- EdDSA-Poseidon2 nonce authorization and seven-key leaf construction;
- binary Merkle membership, configurable depth semantics and index ordering;
- encode-to-BabyJubJub, subgroup rules, non-zero scalar range check and scalar
  multiplication;
- public values: root, depth, RP ID, action, nonce and query point.

### O2: matched World ID nullifier statement

Port `OprfNullifier` to Noir on top of O1. Match all current production checks:

- credential message hash, EdDSA-Poseidon2 signature and blinded-user-ID
  commitment;
- credential expiry and minimum genesis issuance time;
- exact DLog-equality transcript/domain separation;
- response curve/subgroup validation and unblinding equation;
- World ID Proof nullifier hash and output element;
- optional identity commitment rule, signal hash and nonce binding;
- the same public inputs and public nullifier.

Do not keep TACEO's preimage-commitment check unless it is also added to the
Circom contract as a separately named profile. Do not reuse TACEO's `OPRF`
domain separator where World ID uses `World ID Query` or `World ID Proof`.

### OPRF parity tests

- Generate one canonical JSON fixture, then losslessly encode it for both
  frontends.
- Compare the derived query point and nullifier before proof generation.
- Reject mutations to RP ID, action, nonce, registry path/root, authorization
  signature, credential signature/timestamps, DLog response, unblinded point,
  signal hash and identity commitment.
- Include known-answer tests for every Poseidon2 and BabyJubJub boundary so a
  permutation/state-layout mismatch is found without running a full proof.

## Mac WASM qualification gate

Mac Chrome/WASM is the only initial performance target. A profile may be timed
only after:

1. both circuits compile from locked toolchains;
2. the canonical fixture produces identical normalized public outputs;
3. a valid proof verifies and a tampered proof is rejected in each stack;
4. all profile-specific mutation tests fail as expected;
5. the manifest records source commits, compiler/package versions and hashes
   of circuit, witness input, proving material and browser bundle.

Run one untimed warmup followed by five sequential measured samples. Keep P1,
P2 registration, P2 disclosure, O1 and O2 as separate workload identities.
Only promote a qualified immutable bundle to iPhone or E15.
