# WebAuthn passkey P-256 proof

This circuit verifies a WebAuthn assertion signature.

It computes:

```text
SHA256(authenticatorData || SHA256(clientDataJSON))
```

inside Noir, then verifies the resulting digest against a P-256 ECDSA
signature and public key using `noir_bigcurve`.
