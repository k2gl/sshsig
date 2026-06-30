# Changelog

## 1.0.0

- Initial release: verify OpenSSH SSHSIG signatures — `SshsigVerifier::verify()` (the
  `ssh-keygen -Y verify` operation, with `allowed_signers` authorization) and
  `SshsigVerifier::checkNoValidate()` (the `ssh-keygen -Y check-novalidate` operation).
- Supports the `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`, and
  `ecdsa-sha2-nistp256/384/521` signature algorithms, with `sha256` and `sha512` message
  hashing. The legacy SHA-1 `ssh-rsa` algorithm is refused.
- Parses and matches `allowed_signers` files: principals pattern-lists, `namespaces=`,
  `valid-after`/`valid-before` validity windows, and `cert-authority` entries (recorded;
  certificate chains are not yet used to authorize signatures).
- Fail-closed throughout: malformed input, unsupported algorithms, failed cryptographic
  checks, and unauthorized signers all throw a `K2gl\Sshsig\Exception\SshsigException`.
- Zero runtime dependencies: `ext-sodium` for Ed25519, `ext-openssl` for RSA and ECDSA.
