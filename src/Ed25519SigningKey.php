<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\SigningException;
use K2gl\Sshsig\Internal\SshWriter;

/**
 * An Ed25519 {@see SigningKey} backed by ext-sodium. Constructed from a 64-byte
 * libsodium secret key (as produced by sodium_crypto_sign_keypair()).
 */
final class Ed25519SigningKey implements SigningKey
{
    /**
     * @param non-empty-string $secretKey 64-byte libsodium secret key from sodium_crypto_sign_keypair()
     */
    public function __construct(private readonly string $secretKey)
    {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SigningException(
                'Ed25519 secret key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes.'
            );
        }
    }

    public function publicKey(): SshPublicKey
    {
        $raw = sodium_crypto_sign_publickey_from_secretkey($this->secretKey);
        $blob = (new SshWriter)
            ->putString('ssh-ed25519')
            ->putString($raw)
            ->bytes();

        return SshPublicKey::fromBlob($blob);
    }

    public function signTosign(string $tosign, string $hashAlgorithm): array
    {
        return ['ssh-ed25519', sodium_crypto_sign_detached($tosign, $this->secretKey)];
    }
}
