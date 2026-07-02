# Changelog

## 1.2.0

- Add `OpensshPrivateKey::fromFile()` / `::fromString()` — loads a `SigningKey` straight from an
  unencrypted `ssh-ed25519` `openssh-key-v1` container, the format `ssh-keygen` writes by default,
  so a key on disk (e.g. `~/.ssh/id_ed25519`) no longer needs manual extraction before signing.
  Encrypted containers (no `bcrypt_pbkdf` available) and RSA/ECDSA containers throw
  `UnsupportedAlgorithmException` rather than a silent partial read.

## 1.1.0

- Add **signing** — `SshsigSigner` produces armored SSHSIG signatures (the `ssh-keygen -Y sign`
  operation) over a pluggable `SigningKey`: `Ed25519SigningKey` (ext-sodium) and
  `OpensslSigningKey` (RSA `rsa-sha2-256`/`512` and ECDSA `nistp256/384/521` via ext-openssl).
  Output is byte-compatible with `ssh-keygen -Y verify`; the test suite cross-checks every
  algorithm against the OpenSSH CLI.
- `SshsigSigner::publicKey()` exposes the matching `SshPublicKey` (e.g. to build an
  `allowed_signers` line).

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
