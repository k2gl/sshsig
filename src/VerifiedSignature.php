<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

/**
 * The result of a successful {@see SshsigVerifier::verify()}: the identity and
 * namespace that were checked, the signer's public key, and the matching
 * allowed_signers principals pattern.
 */
final class VerifiedSignature
{
    public function __construct(
        public readonly string $identity,
        public readonly string $namespace,
        public readonly SshPublicKey $publicKey,
        public readonly string $principals,
    ) {}
}
