<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\SigningException;
use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;
use K2gl\Sshsig\Internal\SshReader;

/**
 * Loads a {@see SigningKey} from an OpenSSH private key container
 * (`-----BEGIN OPENSSH PRIVATE KEY-----`), the format `ssh-keygen` writes by
 * default — so a key straight off disk (e.g. `~/.ssh/id_ed25519`) can be
 * handed to {@see SshsigSigner} without manual extraction.
 *
 * Scope: unencrypted (`ciphername: none`) ssh-ed25519 containers. Encrypted
 * containers use OpenSSH's bcrypt_pbkdf, which neither ext-openssl nor
 * ext-sodium provide; RSA/ECDSA containers need DER reconstruction from raw
 * components. Both throw {@see UnsupportedAlgorithmException} rather than a
 * silent partial read.
 *
 * @see https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key
 */
final class OpensshPrivateKey
{
    private const MAGIC = "openssh-key-v1\0";

    private const BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----';

    private const END = '-----END OPENSSH PRIVATE KEY-----';

    public static function fromFile(string $path): SigningKey
    {
        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw new SigningException(sprintf('Could not read private key file "%s".', $path));
        }

        return self::fromString($contents);
    }

    public static function fromString(string $armored): SigningKey
    {
        $reader = new SshReader(self::decodeArmor($armored));

        if ($reader->readBytes(strlen(self::MAGIC)) !== self::MAGIC) {
            throw new SigningException('Not an OpenSSH private key (missing "openssh-key-v1" magic).');
        }
        $cipherName = $reader->readString();
        $reader->readString(); // kdfname
        $reader->readString(); // kdfoptions
        $numKeys = $reader->readUint32();

        if ($cipherName !== 'none') {
            throw new UnsupportedAlgorithmException(
                'Encrypted OpenSSH private keys are not supported (no bcrypt_pbkdf available).',
            );
        }

        if ($numKeys !== 1) {
            throw new UnsupportedAlgorithmException(
                sprintf('Expected exactly one key in the container, found %d.', $numKeys),
            );
        }
        $reader->readString(); // public key blob; the private section below is authoritative

        return self::parsePrivateSection($reader->readString());
    }

    private static function parsePrivateSection(string $bytes): SigningKey
    {
        $reader = new SshReader($bytes);
        $checkint1 = $reader->readUint32();
        $checkint2 = $reader->readUint32();

        if ($checkint1 !== $checkint2) {
            throw new SigningException('Corrupt OpenSSH private key (checkint mismatch).');
        }
        $keyType = $reader->readString();

        if ($keyType !== 'ssh-ed25519') {
            throw new UnsupportedAlgorithmException(
                sprintf('Unsupported OpenSSH private key type "%s"; only ssh-ed25519 is supported.', $keyType),
            );
        }
        $reader->readString(); // public key (32 bytes); redundant with the secret key below
        $secretKey = $reader->readString();

        if ($secretKey === '') {
            throw new SigningException('Empty ssh-ed25519 secret key in OpenSSH private key.');
        }
        $reader->readString(); // comment
        self::assertValidPadding($reader);

        return new Ed25519SigningKey($secretKey);
    }

    private static function assertValidPadding(SshReader $reader): void
    {
        $expected = 1;

        while (! $reader->isAtEnd()) {
            if ($reader->readByte() !== $expected) {
                throw new SigningException('Corrupt OpenSSH private key (invalid padding).');
            }
            ++$expected;
        }
    }

    private static function decodeArmor(string $armored): string
    {
        $begin = strpos($armored, self::BEGIN);

        if ($begin === false) {
            throw new SigningException('Missing "-----BEGIN OPENSSH PRIVATE KEY-----" marker.');
        }
        $bodyStart = $begin + strlen(self::BEGIN);
        $end = strpos($armored, self::END, $bodyStart);

        if ($end === false) {
            throw new SigningException('Missing "-----END OPENSSH PRIVATE KEY-----" marker.');
        }
        $body = (string) preg_replace('/\s+/', '', substr($armored, $bodyStart, $end - $bodyStart));
        $blob = base64_decode($body, true);

        if ($blob === false || $blob === '') {
            throw new SigningException('OpenSSH private key armor is not valid base64.');
        }

        return $blob;
    }
}
