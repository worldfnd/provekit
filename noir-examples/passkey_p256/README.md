# P-256 passkey challenge proof

This circuit proves a passkey-style P-256 assertion over a committed challenge.

It proves the following statement:

```text
challenge_commitment = SHA256(challenge_secret)
signed_message_digest = SHA256(authenticator_data || challenge_commitment)
ECDSA_P256_verify(pub_key_x, pub_key_y, signature, signed_message_digest)
```

`challenge_secret` and the ECDSA helper witness `r_point_y` are private. The
authenticator data, challenge commitment, public key, and signature are public.
The ECDSA check follows the standard verification equation
`R = (e / s)G + (r / s)Q`, rejects zero/out-of-range `r` and `s`, and checks
`R.x mod n == r`.

This models the core passkey ownership check: a P-256 credential signed a
challenge that is bound in-circuit to a private secret. The circuit uses
`noir_bigcurve`/`noir-bignum` rather than Noir's P-256 ECDSA black box because
ProveKit does not lower that black box yet. The current Mavros revision also
does not support the BigNum/BigCurve comparisons needed for this circuit, so
the browser demo prepares this passkey circuit through ProveKit's Noir frontend.
