# internal/keys

Key management helpers used by the recursive verifier. Providers abstract how
Groth16 proving and verifying keys are sourced so that callers can swap between
local files and remote URLs.
