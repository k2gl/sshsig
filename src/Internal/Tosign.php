<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;

/**
 * Builds the SSHSIG "to be signed" blob — the exact bytes that are signed and
 * verified: the MAGIC preamble, the namespace, the (empty) reserved field, the
 * hash algorithm, and the hash of the message. Shared by the signer and the
 * verifier so both sides agree byte-for-byte.
 *
 * @internal
 */
final class Tosign
{
    private const MAGIC = 'SSHSIG';

    public static function build(string $namespace, string $hashAlgorithm, string $message): string
    {
        return (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString($namespace)
            ->putString('')
            ->putString($hashAlgorithm)
            ->putString(self::hash($hashAlgorithm, $message))
            ->bytes();
    }

    private static function hash(string $hashAlgorithm, string $message): string
    {
        return match ($hashAlgorithm) {
            'sha256' => hash('sha256', $message, true),
            'sha512' => hash('sha512', $message, true),
            default => throw new UnsupportedAlgorithmException(
                sprintf('Unsupported SSHSIG hash algorithm "%s".', $hashAlgorithm)
            ),
        };
    }
}
