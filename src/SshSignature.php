<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;
use K2gl\Sshsig\Internal\Armor;
use K2gl\Sshsig\Internal\SshReader;
use K2gl\Sshsig\Internal\SshWriter;

/**
 * A parsed SSHSIG signature (OpenSSH PROTOCOL.sshsig): the signer's public key,
 * the namespace, the message hash algorithm, and the signature algorithm and
 * bytes. Parsing enforces the MAGIC preamble, version 1, a non-empty namespace,
 * and the absence of trailing bytes.
 */
final class SshSignature
{
    private const MAGIC = 'SSHSIG';

    private function __construct(
        public readonly SshPublicKey $publicKey,
        public readonly string $namespace,
        public readonly string $hashAlgorithm,
        public readonly string $signatureAlgorithm,
        public readonly string $signature,
    ) {}

    public static function fromArmored(string $armored): self
    {
        $reader = new SshReader(Armor::decode($armored));

        if ($reader->readBytes(6) !== self::MAGIC) {
            throw new InvalidSignatureException('Missing SSHSIG magic preamble.');
        }

        if ($reader->readUint32() !== 1) {
            throw new InvalidSignatureException('Unsupported SSHSIG version (expected 1).');
        }
        $publicKeyBlob = $reader->readString();
        $namespace = $reader->readString();
        $reader->readString(); // reserved — always empty; ignored
        $hashAlgorithm = $reader->readString();
        $signatureBlob = $reader->readString();
        $reader->assertAtEnd();

        if ($namespace === '') {
            throw new InvalidSignatureException('SSHSIG namespace must not be empty.');
        }
        $inner = new SshReader($signatureBlob);
        $signatureAlgorithm = $inner->readString();
        $signature = $inner->readString();
        $inner->assertAtEnd();

        return new self(
            publicKey: SshPublicKey::fromBlob($publicKeyBlob),
            namespace: $namespace,
            hashAlgorithm: $hashAlgorithm,
            signatureAlgorithm: $signatureAlgorithm,
            signature: $signature,
        );
    }

    /**
     * The exact bytes the signature is computed over: the MAGIC preamble, the
     * namespace, the (empty) reserved field, the hash algorithm, and the hash of
     * the message.
     */
    public function signedData(string $message): string
    {
        return (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString($this->namespace)
            ->putString('')
            ->putString($this->hashAlgorithm)
            ->putString($this->hashMessage($message))
            ->bytes();
    }

    private function hashMessage(string $message): string
    {
        return match ($this->hashAlgorithm) {
            'sha256' => hash('sha256', $message, true),
            'sha512' => hash('sha512', $message, true),
            default => throw new UnsupportedAlgorithmException(
                sprintf('Unsupported SSHSIG hash algorithm "%s".', $this->hashAlgorithm)
            ),
        };
    }
}
