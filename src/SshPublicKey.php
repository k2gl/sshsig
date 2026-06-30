<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Internal\SshReader;

/**
 * An SSH public key in its wire form, as embedded in an SSHSIG signature or an
 * allowed_signers entry. Carries the key-type name (e.g. "ssh-ed25519") and the
 * raw blob, and computes the standard OpenSSH SHA256 fingerprint.
 */
final class SshPublicKey
{
    private function __construct(
        public readonly string $type,
        public readonly string $blob,
    ) {}

    /** Parse an SSH-wire public-key blob (the bytes behind the base64 in a .pub file). */
    public static function fromBlob(string $blob): self
    {
        $type = (new SshReader($blob))->readString();

        return new self(type: $type, blob: $blob);
    }

    /** Parse a single-line OpenSSH public key: "&lt;type&gt; &lt;base64&gt; [comment]". */
    public static function fromOpensshLine(string $line): self
    {
        $parts = preg_split('/\s+/', trim($line), 3);

        if ($parts === false || count($parts) < 2) {
            throw new InvalidSignatureException('Malformed OpenSSH public key line.');
        }
        $blob = base64_decode($parts[1], true);

        if ($blob === false) {
            throw new InvalidSignatureException('OpenSSH public key is not valid base64.');
        }
        $key = self::fromBlob($blob);

        if ($key->type !== $parts[0]) {
            throw new InvalidSignatureException('OpenSSH public key type does not match its blob.');
        }

        return $key;
    }

    /** The OpenSSH SHA256 fingerprint, e.g. "SHA256:abc…" (base64, unpadded). */
    public function fingerprint(): string
    {
        return 'SHA256:' . rtrim(base64_encode(hash('sha256', $this->blob, true)), '=');
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->blob, $other->blob);
    }
}
