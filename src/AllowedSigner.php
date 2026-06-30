<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use DateTimeImmutable;

/**
 * One parsed line of an allowed_signers file: the principals pattern-list, the
 * signer's public key, and the recognized options (cert-authority flag,
 * namespaces restriction, and validity window).
 */
final class AllowedSigner
{
    public function __construct(
        public readonly string $principals,
        public readonly SshPublicKey $key,
        public readonly bool $certAuthority = false,
        public readonly ?string $namespaces = null,
        public readonly ?DateTimeImmutable $validAfter = null,
        public readonly ?DateTimeImmutable $validBefore = null,
    ) {}
}
