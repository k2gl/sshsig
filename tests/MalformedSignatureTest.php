<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Tests;

use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;
use K2gl\Sshsig\Internal\Armor;
use K2gl\Sshsig\Internal\SshReader;
use K2gl\Sshsig\Internal\SshWriter;
use K2gl\Sshsig\SshSignature;
use K2gl\Sshsig\SshsigVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SshSignature::class)]
#[CoversClass(SshsigVerifier::class)]
#[CoversClass(Armor::class)]
#[CoversClass(SshReader::class)]
#[CoversClass(SshWriter::class)]
final class MalformedSignatureTest extends TestCase
{
    private const NS = 'file';

    public function testRejectsBadArmor(): void
    {
        // act + assert
        fact(static fn () => (new SshsigVerifier)->checkNoValidate('message', 'not a signature', self::NS))
            ->throws(InvalidSignatureException::class);
    }

    public function testRejectsWrongVersion(): void
    {
        // act + assert
        fact(fn () => $this->check(self::blob(version: 2, namespace: self::NS, hashAlgorithm: 'sha512', signatureAlgorithm: 'ssh-ed25519')))
            ->throws(InvalidSignatureException::class);
    }

    public function testRejectsEmptyNamespace(): void
    {
        // act + assert
        fact(fn () => $this->check(self::blob(version: 1, namespace: '', hashAlgorithm: 'sha512', signatureAlgorithm: 'ssh-ed25519')))
            ->throws(InvalidSignatureException::class);
    }

    public function testRejectsTrailingBytes(): void
    {
        // act + assert
        fact(fn () => $this->check(self::blob(version: 1, namespace: self::NS, hashAlgorithm: 'sha512', signatureAlgorithm: 'ssh-ed25519') . 'x'))
            ->throws(InvalidSignatureException::class);
    }

    public function testRejectsUnsupportedSignatureAlgorithm(): void
    {
        // act + assert
        fact(fn () => $this->check(self::blob(version: 1, namespace: self::NS, hashAlgorithm: 'sha512', signatureAlgorithm: 'ssh-rsa')))
            ->throws(UnsupportedAlgorithmException::class);
    }

    public function testRejectsUnsupportedHashAlgorithm(): void
    {
        // act + assert
        fact(fn () => $this->check(self::blob(version: 1, namespace: self::NS, hashAlgorithm: 'md5', signatureAlgorithm: 'ssh-ed25519')))
            ->throws(UnsupportedAlgorithmException::class);
    }

    private function check(string $blob): void
    {
        (new SshsigVerifier)->checkNoValidate('message', self::armor($blob), self::NS);
    }

    private static function armor(string $blob): string
    {
        return "-----BEGIN SSH SIGNATURE-----\n"
            . chunk_split(base64_encode($blob), 70, "\n")
            . "-----END SSH SIGNATURE-----\n";
    }

    private static function blob(int $version, string $namespace, string $hashAlgorithm, string $signatureAlgorithm): string
    {
        $inner = (new SshWriter)
            ->putString($signatureAlgorithm)
            ->putString('signature-bytes')
            ->bytes();

        return (new SshWriter)
            ->putBytes('SSHSIG')
            ->putBytes(pack('N', $version))
            ->putString(self::publicKeyBlob())
            ->putString($namespace)
            ->putString('')
            ->putString($hashAlgorithm)
            ->putString($inner)
            ->bytes();
    }

    private static function publicKeyBlob(): string
    {
        $parts = explode(' ', trim((string) file_get_contents(__DIR__ . '/fixtures/sshsig/ed25519.pub')));

        return (string) base64_decode($parts[1], true);
    }
}
