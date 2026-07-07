<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Tests;

use K2gl\Sshsig\AllowedSigners;
use K2gl\Sshsig\Exception\SignatureVerificationFailed;
use K2gl\Sshsig\Exception\SignerNotAllowedException;
use K2gl\Sshsig\Internal\Armor;
use K2gl\Sshsig\Internal\Der;
use K2gl\Sshsig\Internal\SignaturePrimitive;
use K2gl\Sshsig\Internal\SshReader;
use K2gl\Sshsig\SshPublicKey;
use K2gl\Sshsig\SshSignature;
use K2gl\Sshsig\SshsigVerifier;
use K2gl\Sshsig\VerifiedSignature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SshsigVerifier::class)]
#[CoversClass(SshSignature::class)]
#[CoversClass(SshPublicKey::class)]
#[CoversClass(VerifiedSignature::class)]
#[CoversClass(SignaturePrimitive::class)]
#[CoversClass(Der::class)]
#[CoversClass(Armor::class)]
#[CoversClass(SshReader::class)]
final class SshsigVerifierTest extends TestCase
{
    private const ID = 'alice@example.com';
    private const NS = 'file';

    /** @return iterable<string, array{string, string}> */
    public static function signatures(): iterable
    {
        yield 'ed25519' => ['ed25519.sig', 'ssh-ed25519'];
        yield 'ed25519 (sha256)' => ['ed25519-sha256.sig', 'ssh-ed25519'];
        yield 'rsa-sha2-512' => ['rsa-sha2-512.sig', 'rsa-sha2-512'];
        yield 'rsa-sha2-256' => ['rsa-sha2-256.sig', 'rsa-sha2-256'];
        yield 'ecdsa nistp256' => ['ecdsa-nistp256.sig', 'ecdsa-sha2-nistp256'];
        yield 'ecdsa nistp384' => ['ecdsa-nistp384.sig', 'ecdsa-sha2-nistp384'];
        yield 'ecdsa nistp521' => ['ecdsa-nistp521.sig', 'ecdsa-sha2-nistp521'];
    }

    #[DataProvider('signatures')]
    public function testVerifiesRealSignatures(string $signatureFile, string $algorithm): void
    {
        $result = (new SshsigVerifier)->verify(
            message: self::fixture('message.txt'),
            armoredSignature: self::fixture($signatureFile),
            allowedSigners: AllowedSigners::fromString(self::fixture('allowed_signers')),
            identity: self::ID,
            namespace: self::NS,
        );

        fact($result instanceof VerifiedSignature)->true();
        fact($result->identity)->is(self::ID);
        fact($result->namespace)->is(self::NS);
        fact($result->principals)->is(self::ID);
    }

    #[DataProvider('signatures')]
    public function testCheckNoValidateExposesTheParsedSignature(string $signatureFile, string $algorithm): void
    {
        $signature = (new SshsigVerifier)->checkNoValidate(
            self::fixture('message.txt'),
            self::fixture($signatureFile),
            self::NS,
        );

        fact($signature->signatureAlgorithm)->is($algorithm);
        fact($signature->namespace)->is(self::NS);
        fact(str_starts_with($signature->publicKey->fingerprint(), 'SHA256:'))->true();
    }

    public function testRejectsTamperedMessage(): void
    {
        // act + assert
        fact(static fn () => (new SshsigVerifier)->checkNoValidate('tampered', self::fixture('ed25519.sig'), self::NS))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testRejectsWrongNamespace(): void
    {
        // act + assert
        fact(static fn () => (new SshsigVerifier)->checkNoValidate(self::fixture('message.txt'), self::fixture('ed25519.sig'), 'git'))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testRejectsUnknownIdentity(): void
    {
        // act + assert
        fact(static fn () => (new SshsigVerifier)->verify(
            message: self::fixture('message.txt'),
            armoredSignature: self::fixture('ed25519.sig'),
            allowedSigners: AllowedSigners::fromString(self::fixture('allowed_signers')),
            identity: 'bob@example.com',
            namespace: self::NS,
        ))->throws(SignerNotAllowedException::class);
    }

    public function testRejectsUnauthorizedKey(): void
    {
        // arrange
        $allowed = self::ID . ' ' . trim(self::fixture('other.pub'));

        // act + assert
        fact(static fn () => (new SshsigVerifier)->verify(
            message: self::fixture('message.txt'),
            armoredSignature: self::fixture('ed25519.sig'),
            allowedSigners: AllowedSigners::fromString($allowed),
            identity: self::ID,
            namespace: self::NS,
        ))->throws(SignerNotAllowedException::class);
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/sshsig/' . $name);
        fact($contents)->isString();

        return (string) $contents;
    }
}
