# k2gl/sshsig

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sshsig/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sshsig/actions)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sshsig)](https://packagist.org/packages/k2gl/sshsig)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/sshsig)](https://packagist.org/packages/k2gl/sshsig)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%209-2a5ea7)](https://phpstan.org/)
[![License](https://img.shields.io/packagist/l/k2gl/sshsig)](https://packagist.org/packages/k2gl/sshsig)

Faithful, zero-dependency PHP implementation of the **OpenSSH SSHSIG** signature format — the
signatures produced by `ssh-keygen -Y sign` and used for **Git commit/tag signing** and file
signing. It **verifies** signatures (parsing the armor and SSH wire format, then authorizing the
signer against an `allowed_signers` file, mirroring `ssh-keygen -Y verify`) and **signs**
messages with byte-output compatible with `ssh-keygen -Y verify`.

Fail-closed by design: anything malformed, unsupported, cryptographically invalid, or
unauthorized throws — nothing is ever silently treated as verified.

## Install

```bash
composer require k2gl/sshsig
```

Requires PHP 8.1+ with `ext-sodium` (Ed25519) and `ext-openssl` (RSA and ECDSA) — both are
bundled with most PHP builds.

## Usage

### Verify a signature against an allowed_signers file

This is the equivalent of `ssh-keygen -Y verify -f allowed_signers -I <identity> -n <namespace>`.

```php
use K2gl\Sshsig\AllowedSigners;
use K2gl\Sshsig\Exception\SshsigException;
use K2gl\Sshsig\SshsigVerifier;

$verifier = new SshsigVerifier;

try {
    $result = $verifier->verify(
        message: file_get_contents('release.tar.gz'),
        armoredSignature: file_get_contents('release.tar.gz.sig'),
        allowedSigners: AllowedSigners::fromFile('allowed_signers'),
        identity: 'alice@example.com',
        namespace: 'file',
    );

    echo "Verified: {$result->publicKey->fingerprint()}\n";
} catch (SshsigException $e) {
    // not verified — malformed, unsupported, bad signature, or unauthorized signer
    echo "Rejected: {$e->getMessage()}\n";
}
```

### Check a signature without authorizing the signer

The equivalent of `ssh-keygen -Y check-novalidate -n <namespace>`: confirm the signature is
structurally sound and cryptographically valid under its own embedded key, then inspect it.

```php
$signature = $verifier->checkNoValidate($message, $armoredSignature, namespace: 'git');

echo $signature->signatureAlgorithm;          // e.g. "ssh-ed25519"
echo $signature->publicKey->fingerprint();    // "SHA256:…"
```

### Sign a message

Produce an SSHSIG signature (the `ssh-keygen -Y sign` operation). Provide the signing key —
Ed25519 (a 64-byte libsodium secret key) or an OpenSSL RSA/ECDSA private key:

```php
use K2gl\Sshsig\Ed25519SigningKey;
use K2gl\Sshsig\OpensslSigningKey;
use K2gl\Sshsig\SshsigSigner;

// Ed25519
$keypair = sodium_crypto_sign_keypair();
$signer = new SshsigSigner(new Ed25519SigningKey(sodium_crypto_sign_secretkey($keypair)));

// …or RSA / ECDSA from an OpenSSL private key (PEM)
$signer = new SshsigSigner(OpensslSigningKey::fromPem(file_get_contents('id_rsa')));

$armored = $signer->sign($message, namespace: 'file');          // sha512 by default
file_put_contents('message.sig', $armored);

// the resulting signature verifies with `ssh-keygen -Y verify` and with this library
```

`$signer->publicKey()` returns the matching `SshPublicKey` (e.g. to build an `allowed_signers`
line). The default hash is `sha512`; pass `hashAlgorithm: 'sha256'` to switch.

### Inspect or build allowed_signers in memory

```php
$allowed = AllowedSigners::fromString(<<<TXT
    # comments and blank lines are ignored
    alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
    *@example.com namespaces="git,file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
    TXT);
```

## Design

- **Fail-closed.** Every failure path throws a `K2gl\Sshsig\Exception\SshsigException`
  (`InvalidSignatureException`, `UnsupportedAlgorithmException`, `SignatureVerificationFailed`,
  `SignerNotAllowedException`). A returned value always means verified.
- **Spec-faithful.** Implements OpenSSH `PROTOCOL.sshsig`: the `SSHSIG` magic preamble,
  version 1, the `to-be-signed` blob (namespace + reserved + hash algorithm + message hash),
  and the armor.
- **Algorithms.** `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`,
  `ecdsa-sha2-nistp256/384/521`; `sha256` and `sha512` message hashing. The legacy SHA-1
  `ssh-rsa` signature algorithm is refused.
- **`allowed_signers`.** Principals pattern-lists, `namespaces=`, `valid-after`/`valid-before`
  validity windows, and `cert-authority` entries (parsed and recorded; certificate-chain
  verification is not yet performed).
- **Signing.** `SshsigSigner` over a pluggable `SigningKey` (Ed25519 via ext-sodium; RSA and
  ECDSA via ext-openssl), producing armor byte-compatible with `ssh-keygen -Y verify`.
- **Zero dependencies.** Pure PHP over `ext-sodium` and `ext-openssl`; no `phpseclib`.
- **Verified against OpenSSH.** The test suite verifies real `ssh-keygen -Y sign` output for
  every supported algorithm, plus tampered, wrong-namespace, unauthorized, and malformed cases.

## License

MIT. See [LICENSE](LICENSE).
