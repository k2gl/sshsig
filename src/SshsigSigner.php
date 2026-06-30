<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Internal\Armor;
use K2gl\Sshsig\Internal\SshWriter;
use K2gl\Sshsig\Internal\Tosign;

/**
 * Produces OpenSSH SSHSIG signatures (the `ssh-keygen -Y sign` operation):
 * builds the "to be signed" blob, signs it with the given {@see SigningKey},
 * and returns the armored signature. The output is byte-compatible with
 * `ssh-keygen -Y verify`.
 */
final class SshsigSigner
{
    public function __construct(private readonly SigningKey $key) {}

    public function publicKey(): SshPublicKey
    {
        return $this->key->publicKey();
    }

    /**
     * Sign a message under a namespace and return the armored signature.
     *
     * @param string $hashAlgorithm "sha512" (default) or "sha256"
     */
    public function sign(string $message, string $namespace, string $hashAlgorithm = 'sha512'): string
    {
        if ($namespace === '') {
            throw new InvalidSignatureException('SSHSIG namespace must not be empty.');
        }
        $tosign = Tosign::build($namespace, $hashAlgorithm, $message);
        [$signatureAlgorithm, $signatureBytes] = $this->key->signTosign($tosign, $hashAlgorithm);

        $signatureBlob = (new SshWriter)
            ->putString($signatureAlgorithm)
            ->putString($signatureBytes)
            ->bytes();

        $blob = (new SshWriter)
            ->putBytes('SSHSIG')
            ->putBytes(pack('N', 1))
            ->putString($this->key->publicKey()->blob)
            ->putString($namespace)
            ->putString('')
            ->putString($hashAlgorithm)
            ->putString($signatureBlob)
            ->bytes();

        return Armor::encode($blob);
    }
}
